package layer

import (
	"context"
	"errors"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
)

type (
	findParams struct {
		attr   string
		val    string
		cid    *cid.ID
		prefix string
	}

	getParams struct {
		io.Writer
		*object.Range

		offset int64
		length int64
		cid    *cid.ID
		oid    *object.ID
	}

	// ListObjectsParamsCommon contains common parameters for ListObjectsV1 and ListObjectsV2.
	ListObjectsParamsCommon struct {
		Bucket    string
		Delimiter string
		Encode    string
		MaxKeys   int
		Prefix    string
	}

	// ListObjectsParamsV1 contains params for ListObjectsV1.
	ListObjectsParamsV1 struct {
		ListObjectsParamsCommon
		Marker string
	}

	// ListObjectsParamsV2 contains params for ListObjectsV2.
	ListObjectsParamsV2 struct {
		ListObjectsParamsCommon
		ContinuationToken string
		StartAfter        string
		FetchOwner        bool
	}

	allObjectParams struct {
		Bucket    *api.BucketInfo
		Delimiter string
		Prefix    string
	}
)

// objectSearch returns all available objects by search params.
func (n *layer) objectSearch(ctx context.Context, p *findParams) ([]*object.ID, error) {
	var opts object.SearchFilters

	opts.AddRootFilter()

	if filename, err := url.QueryUnescape(p.val); err != nil {
		return nil, err
	} else if filename != "" {
		if p.attr == "" {
			opts.AddFilter(object.AttributeFileName, filename, object.MatchStringEqual)
		} else {
			opts.AddFilter(p.attr, filename, object.MatchStringEqual)
		}
	}
	if prefix, err := url.QueryUnescape(p.prefix); err != nil {
		return nil, err
	} else if prefix != "" {
		opts.AddFilter(object.AttributeFileName, prefix, object.MatchCommonPrefix)
	}
	return n.pool.SearchObject(ctx, new(client.SearchObjectParams).WithContainerID(p.cid).WithSearchFilters(opts), n.BearerOpt(ctx))
}

// objectFindID returns object id (uuid) based on it's nice name in s3. If
// nice name is uuid compatible, then function returns it.
func (n *layer) objectFindID(ctx context.Context, p *findParams) (*object.ID, error) {
	if result, err := n.objectSearch(ctx, p); err != nil {
		return nil, err
	} else if ln := len(result); ln == 0 {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	} else if ln == 1 {
		return result[0], nil
	}

	return nil, errors.New("several objects with the same name found")
}

func newAddress(cid *cid.ID, oid *object.ID) *object.Address {
	address := object.NewAddress()
	address.SetContainerID(cid)
	address.SetObjectID(oid)
	return address
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, cid *cid.ID, oid *object.ID) (*object.Object, error) {
	ops := new(client.ObjectHeaderParams).WithAddress(newAddress(cid, oid)).WithAllFields()
	return n.pool.GetObjectHeader(ctx, ops, n.BearerOpt(ctx))
}

// objectGet and write it into provided io.Reader.
func (n *layer) objectGet(ctx context.Context, p *getParams) (*object.Object, error) {
	// prepare length/offset writer
	w := newWriter(p.Writer, p.offset, p.length)
	ops := new(client.GetObjectParams).WithAddress(newAddress(p.cid, p.oid)).WithPayloadWriter(w)
	return n.pool.GetObject(ctx, ops, n.BearerOpt(ctx))
}

// objectRange gets object range and writes it into provided io.Writer.
func (n *layer) objectRange(ctx context.Context, p *getParams) ([]byte, error) {
	w := newWriter(p.Writer, p.offset, p.length)
	ops := new(client.RangeDataParams).WithAddress(newAddress(p.cid, p.oid)).WithDataWriter(w).WithRange(p.Range)
	return n.pool.ObjectPayloadRangeData(ctx, ops, n.BearerOpt(ctx))
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, bkt *api.BucketInfo, p *PutObjectParams) (*api.ObjectInfo, error) {
	own := n.Owner(ctx)
	obj, err := url.QueryUnescape(p.Object)
	if err != nil {
		return nil, err
	}

	versioningEnabled := n.isVersioningEnabled(ctx, bkt)
	versions, err := n.headVersions(ctx, bkt, obj)
	if err != nil && !apiErrors.IsS3Error(err, apiErrors.ErrNoSuchKey) {
		return nil, err
	}
	idsToDeleteArr := updateCRDT2PSetHeaders(p, versions, versioningEnabled)

	r := p.Reader
	if len(p.Header[api.ContentType]) == 0 {
		d := newDetector(r)
		if contentType, err := d.Detect(); err == nil {
			p.Header[api.ContentType] = contentType
		}
		r = d.MultiReader()
	}
	rawObject := formRawObject(p, bkt.CID, own, obj)

	ops := new(client.PutObjectParams).WithObject(rawObject.Object()).WithPayloadReader(r)
	oid, err := n.pool.PutObject(ctx, ops, n.BearerOpt(ctx))
	if err != nil {
		return nil, err
	}

	if p.Header[versionsDeleteMarkAttr] == delMarkFullObject {
		if last := versions.getLast(); last != nil {
			n.objCache.Delete(last.Address())
		}
	}

	meta, err := n.objectHead(ctx, bkt.CID, oid)
	if err != nil {
		return nil, err
	}

	if err = n.objCache.Put(*meta); err != nil {
		n.log.Error("couldn't cache an object", zap.Error(err))
	}

	for _, id := range idsToDeleteArr {
		if err = n.objectDelete(ctx, bkt.CID, id); err != nil {
			n.log.Warn("couldn't delete object",
				zap.Stringer("version id", id),
				zap.Error(err))
		}
		if !versioningEnabled {
			if objVersion := versions.getVersion(id); objVersion != nil {
				if err = n.DeleteObjectTagging(ctx, objVersion); err != nil {
					n.log.Warn("couldn't delete object tagging",
						zap.Stringer("version id", id),
						zap.Error(err))
				}
			}
		}
	}

	return &api.ObjectInfo{
		ID:  oid,
		CID: bkt.CID,

		Owner:         own,
		Bucket:        p.Bucket,
		Name:          p.Object,
		Size:          p.Size,
		Created:       time.Now(),
		CreationEpoch: meta.CreationEpoch(),
		Headers:       p.Header,
		ContentType:   p.Header[api.ContentType],
		HashSum:       meta.PayloadChecksum().String(),
	}, nil
}

func formRawObject(p *PutObjectParams, bktID *cid.ID, own *owner.ID, obj string) *object.RawObject {
	attributes := make([]*object.Attribute, 0, len(p.Header)+2)
	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(obj)

	createdAt := object.NewAttribute()
	createdAt.SetKey(object.AttributeTimestamp)
	createdAt.SetValue(strconv.FormatInt(time.Now().UTC().Unix(), 10))

	attributes = append(attributes, filename, createdAt)

	for k, v := range p.Header {
		ua := object.NewAttribute()
		ua.SetKey(k)
		ua.SetValue(v)

		attributes = append(attributes, ua)
	}

	raw := object.NewRaw()
	raw.SetOwnerID(own)
	raw.SetContainerID(bktID)
	raw.SetAttributes(attributes...)

	return raw
}

func updateCRDT2PSetHeaders(p *PutObjectParams, versions *objectVersions, versioningEnabled bool) []*object.ID {
	var idsToDeleteArr []*object.ID
	if versions == nil {
		return idsToDeleteArr
	}

	if versioningEnabled {
		if len(versions.addList) != 0 {
			p.Header[versionsAddAttr] = versions.getAddHeader()
		}

		deleted := versions.getDelHeader()
		// p.Header[versionsDelAttr] can be not empty when deleting specific version
		if delAttr := p.Header[versionsDelAttr]; len(delAttr) != 0 {
			if len(deleted) != 0 {
				p.Header[versionsDelAttr] = deleted + "," + delAttr
			} else {
				p.Header[versionsDelAttr] = delAttr
			}
		} else if len(deleted) != 0 {
			p.Header[versionsDelAttr] = deleted
		}
	} else {
		versionsDeletedStr := versions.getDelHeader()
		if len(versionsDeletedStr) != 0 {
			versionsDeletedStr += ","
		}

		if lastVersion := versions.getLast(); lastVersion != nil {
			p.Header[versionsDelAttr] = versionsDeletedStr + lastVersion.Version()
			idsToDeleteArr = append(idsToDeleteArr, lastVersion.ID)
		} else if len(versionsDeletedStr) != 0 {
			p.Header[versionsDelAttr] = versionsDeletedStr
		}

		for _, version := range versions.objects {
			if contains(versions.delList, version.Version()) {
				idsToDeleteArr = append(idsToDeleteArr, version.ID)
			}
		}
	}

	return idsToDeleteArr
}

func (n *layer) headLastVersionIfNotDeleted(ctx context.Context, bkt *api.BucketInfo, objectName string) (*api.ObjectInfo, error) {
	if address := n.namesCache.Get(bkt.Name + "/" + objectName); address != nil {
		if headInfo := n.objCache.Get(address); headInfo != nil {
			return objInfoFromMeta(bkt, headInfo), nil
		}
	}

	versions, err := n.headVersions(ctx, bkt, objectName)
	if err != nil {
		return nil, err
	}

	lastVersion := versions.getLast()
	if lastVersion == nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	}

	if err = n.namesCache.Put(lastVersion.NiceName(), lastVersion.Address()); err != nil {
		n.log.Warn("couldn't put obj address to head cache",
			zap.String("obj nice name", lastVersion.NiceName()),
			zap.Error(err))
	}

	return lastVersion, nil
}

func (n *layer) headVersions(ctx context.Context, bkt *api.BucketInfo, objectName string) (*objectVersions, error) {
	ids, err := n.objectSearch(ctx, &findParams{cid: bkt.CID, val: objectName})
	if err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	}

	versions := newObjectVersions(objectName)
	for _, id := range ids {
		meta, err := n.objectHead(ctx, bkt.CID, id)
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", bkt.CID),
				zap.Error(err))
			continue
		}
		if err = n.objCache.Put(*meta); err != nil {
			n.log.Warn("couldn't put meta to objects cache",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", bkt.CID),
				zap.Error(err))
		}

		if oi := objectInfoFromMeta(bkt, meta, "", ""); oi != nil {
			if isSystem(oi) {
				continue
			}
			versions.appendVersion(oi)
		}
	}

	return versions, nil
}

func (n *layer) headVersion(ctx context.Context, bkt *api.BucketInfo, versionID string) (*api.ObjectInfo, error) {
	oid := object.NewID()
	if err := oid.Parse(versionID); err != nil {
		return nil, err
	}

	if headInfo := n.objCache.Get(newAddress(bkt.CID, oid)); headInfo != nil {
		return objInfoFromMeta(bkt, headInfo), nil
	}

	meta, err := n.objectHead(ctx, bkt.CID, oid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
		return nil, err
	}

	objInfo := objectInfoFromMeta(bkt, meta, "", "")
	if err = n.objCache.Put(*meta); err != nil {
		n.log.Warn("couldn't put obj to object cache",
			zap.String("bucket name", objInfo.Bucket),
			zap.Stringer("bucket cid", objInfo.CID),
			zap.String("object name", objInfo.Name),
			zap.Stringer("object id", objInfo.ID),
			zap.Error(err))
	}

	return objInfo, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, cid *cid.ID, oid *object.ID) error {
	address := newAddress(cid, oid)
	dop := new(client.DeleteObjectParams)
	dop.WithAddress(address)
	n.objCache.Delete(address)
	return n.pool.DeleteObject(ctx, dop, n.BearerOpt(ctx))
}

// ListObjectsV1 returns objects in a bucket for requests of Version 1.
func (n *layer) ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error) {
	var (
		err        error
		result     ListObjectsInfoV1
		allObjects []*api.ObjectInfo
	)

	if p.MaxKeys == 0 {
		return &result, nil
	}

	if allObjects, err = n.listAllObjects(ctx, p.ListObjectsParamsCommon); err != nil {
		return nil, err
	}

	if len(allObjects) == 0 {
		return &result, nil
	}

	if p.Marker != "" {
		allObjects = trimAfterObjectName(p.Marker, allObjects)
	}

	if len(allObjects) > p.MaxKeys {
		result.IsTruncated = true
		allObjects = allObjects[:p.MaxKeys]
		result.NextMarker = allObjects[len(allObjects)-1].Name
	}

	result.Prefixes, result.Objects = triageObjects(allObjects)

	return &result, nil
}

// ListObjectsV2 returns objects in a bucket for requests of Version 2.
func (n *layer) ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error) {
	var (
		err        error
		result     ListObjectsInfoV2
		allObjects []*api.ObjectInfo
	)

	if p.MaxKeys == 0 {
		return &result, nil
	}

	if allObjects, err = n.listAllObjects(ctx, p.ListObjectsParamsCommon); err != nil {
		return nil, err
	}

	if len(allObjects) == 0 {
		return &result, nil
	}

	if p.ContinuationToken != "" {
		allObjects = trimAfterObjectID(p.ContinuationToken, allObjects)
	}

	if p.StartAfter != "" {
		allObjects = trimAfterObjectName(p.StartAfter, allObjects)
	}

	if len(allObjects) > p.MaxKeys {
		result.IsTruncated = true
		allObjects = allObjects[:p.MaxKeys]
		result.NextContinuationToken = allObjects[len(allObjects)-1].ID.String()
	}

	result.Prefixes, result.Objects = triageObjects(allObjects)

	return &result, nil
}

func (n *layer) listSortedObjects(ctx context.Context, p allObjectParams) ([]*api.ObjectInfo, error) {
	versions, err := n.getAllObjectsVersions(ctx, p.Bucket, p.Prefix, p.Delimiter)
	if err != nil {
		return nil, err
	}

	objects := make([]*api.ObjectInfo, 0, len(versions))
	for _, v := range versions {
		lastVersion := v.getLast()
		if lastVersion != nil {
			objects = append(objects, lastVersion)
		}
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	return objects, nil
}

func (n *layer) getAllObjectsVersions(ctx context.Context, bkt *api.BucketInfo, prefix, delimiter string) (map[string]*objectVersions, error) {
	var err error

	cacheKey := cache.CreateObjectsListCacheKey(bkt.CID, prefix)
	ids := n.listsCache.Get(cacheKey)

	if ids == nil {
		ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID, prefix: prefix})
		if err != nil {
			return nil, err
		}
		if err := n.listsCache.Put(cacheKey, ids); err != nil {
			n.log.Error("couldn't cache list of objects", zap.Error(err))
		}
	}

	versions := make(map[string]*objectVersions, len(ids)/2)

	for i := 0; i < len(ids); i++ {
		if ids[i] == nil {
			continue
		}
		obj := n.objectFromObjectsCacheOrNeoFS(ctx, bkt.CID, ids[i])
		if obj == nil {
			// mark ids[i] as an address of invalid object
			ids[i] = nil
			continue
		}
		if oi := objectInfoFromMeta(bkt, obj, prefix, delimiter); oi != nil {
			if isSystem(oi) {
				continue
			}

			objVersions, ok := versions[oi.Name]
			if !ok {
				objVersions = newObjectVersions(oi.Name)
			}
			objVersions.appendVersion(oi)
			versions[oi.Name] = objVersions
		}
	}

	return versions, nil
}

func getExistedVersions(versions *objectVersions) []string {
	var res []string
	for _, add := range versions.addList {
		if !contains(versions.delList, add) {
			res = append(res, add)
		}
	}
	return res
}

func splitVersions(header string) []string {
	if len(header) == 0 {
		return nil
	}

	return strings.Split(header, ",")
}

func isSystem(obj *api.ObjectInfo) bool {
	return len(obj.Headers[objectSystemAttributeName]) > 0 ||
		len(obj.Headers[attrVersionsIgnore]) > 0
}

func trimAfterObjectName(startAfter string, objects []*api.ObjectInfo) []*api.ObjectInfo {
	if len(objects) != 0 && objects[len(objects)-1].Name <= startAfter {
		return nil
	}
	for i := range objects {
		if objects[i].Name > startAfter {
			return objects[i:]
		}
	}

	return nil
}

func trimAfterObjectID(id string, objects []*api.ObjectInfo) []*api.ObjectInfo {
	if len(objects) != 0 && objects[len(objects)-1].ID.String() == id {
		return []*api.ObjectInfo{}
	}
	for i, obj := range objects {
		if obj.ID.String() == id {
			return objects[i+1:]
		}
	}

	return nil
}

func triageObjects(allObjects []*api.ObjectInfo) (prefixes []string, objects []*api.ObjectInfo) {
	for _, ov := range allObjects {
		if ov.IsDir {
			prefixes = append(prefixes, ov.Name)
		} else {
			objects = append(objects, ov)
		}
	}

	return
}

func (n *layer) listAllObjects(ctx context.Context, p ListObjectsParamsCommon) ([]*api.ObjectInfo, error) {
	var (
		err        error
		bkt        *api.BucketInfo
		allObjects []*api.ObjectInfo
	)

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	}

	allObjects, err = n.listSortedObjects(ctx, allObjectParams{
		Bucket:    bkt,
		Prefix:    p.Prefix,
		Delimiter: p.Delimiter,
	})
	if err != nil {
		return nil, err
	}

	return allObjects, nil
}

func (n *layer) isVersioningEnabled(ctx context.Context, bktInfo *api.BucketInfo) bool {
	settings, err := n.getBucketSettings(ctx, bktInfo)
	if err != nil {
		n.log.Warn("couldn't get versioning settings object", zap.Error(err))
		return false
	}

	return settings.VersioningEnabled
}

func (n *layer) objectFromObjectsCacheOrNeoFS(ctx context.Context, cid *cid.ID, oid *object.ID) *object.Object {
	var (
		err  error
		meta = n.objCache.Get(newAddress(cid, oid))
	)
	if meta == nil {
		meta, err = n.objectHead(ctx, cid, oid)
		if err != nil {
			n.log.Warn("could not fetch object meta", zap.Error(err))
			return nil
		}
		if err = n.objCache.Put(*meta); err != nil {
			n.log.Error("couldn't cache an object", zap.Error(err))
		}
	}

	return meta
}
