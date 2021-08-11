package layer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
)

type (
	findParams struct {
		val string
		cid *cid.ID
	}

	getParams struct {
		io.Writer
		*object.Range

		offset  int64
		length  int64
		address *object.Address
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
		Bucket    *BucketInfo
		Delimiter string
		Prefix    string
	}
)

const (
	versionsDelAttr        = "S3-Versions-del"
	versionsAddAttr        = "S3-Versions-add"
	versionsDeleteMarkAttr = "S3-Versions-delete-mark"
)

// objectSearch returns all available objects by search params.
func (n *layer) objectSearch(ctx context.Context, p *findParams) ([]*object.ID, error) {
	var opts object.SearchFilters

	opts.AddRootFilter()

	if filename, err := url.QueryUnescape(p.val); err != nil {
		return nil, err
	} else if filename != "" {
		opts.AddFilter(object.AttributeFileName, filename, object.MatchStringEqual)
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

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, cid *cid.ID, oid *object.ID) (*object.Object, error) {
	address := object.NewAddress()
	address.SetContainerID(cid)
	address.SetObjectID(oid)
	ops := new(client.ObjectHeaderParams).WithAddress(address).WithAllFields()
	return n.pool.GetObjectHeader(ctx, ops, n.BearerOpt(ctx))
}

// objectGet and write it into provided io.Reader.
func (n *layer) objectGet(ctx context.Context, p *getParams) (*object.Object, error) {
	// prepare length/offset writer
	w := newWriter(p.Writer, p.offset, p.length)
	ops := new(client.GetObjectParams).WithAddress(p.address).WithPayloadWriter(w)
	return n.pool.GetObject(ctx, ops, n.BearerOpt(ctx))
}

// objectRange gets object range and writes it into provided io.Writer.
func (n *layer) objectRange(ctx context.Context, p *getParams) ([]byte, error) {
	w := newWriter(p.Writer, p.offset, p.length)
	ops := new(client.RangeDataParams).WithAddress(p.address).WithDataWriter(w).WithRange(p.Range)
	return n.pool.ObjectPayloadRangeData(ctx, ops, n.BearerOpt(ctx))
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, bkt *BucketInfo, p *PutObjectParams) (*ObjectInfo, error) {
	var (
		err error
		obj string
		own = n.Owner(ctx)
	)

	if p.Object == bktVersionSettingsObject {
		return nil, fmt.Errorf("trying put bucket settings object")
	}

	if obj, err = url.QueryUnescape(p.Object); err != nil {
		return nil, err
	}

	versioningEnabled := n.isVersioningEnabled(ctx, bkt)
	lastVersionInfo, err := n.headLastVersion(ctx, bkt, p.Object)
	if err != nil && !apiErrors.IsS3Error(err, apiErrors.ErrNoSuchKey) {
		return nil, err
	}

	attributes := make([]*object.Attribute, 0, len(p.Header)+1)
	var idsToDeleteArr []*object.ID
	if lastVersionInfo != nil {
		if versioningEnabled {
			versionsAddedStr := lastVersionInfo.Headers[versionsAddAttr]
			if len(versionsAddedStr) != 0 {
				versionsAddedStr += ","
			}
			versionsAddedStr += lastVersionInfo.ID().String()
			p.Header[versionsAddAttr] = versionsAddedStr

			deleted := p.Header[versionsDelAttr]
			if delVersions := lastVersionInfo.Headers[versionsDelAttr]; len(delVersions) != 0 {
				if len(deleted) == 0 {
					deleted = delVersions
				} else {
					deleted = delVersions + "," + deleted
				}
			}
			if len(deleted) != 0 {
				p.Header[versionsDelAttr] = deleted
			}
		} else {
			versionsDeletedStr := lastVersionInfo.Headers[versionsDelAttr]
			if len(versionsDeletedStr) != 0 {
				versionsDeletedStr += ","
			}
			versionsDeletedStr += lastVersionInfo.ID().String()
			p.Header[versionsDelAttr] = versionsDeletedStr

			idsToDeleteArr = append(idsToDeleteArr, lastVersionInfo.ID())
		}
	}

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
	raw.SetContainerID(bkt.CID)
	raw.SetAttributes(attributes...)

	r := newDetector(p.Reader)

	ops := new(client.PutObjectParams).WithObject(raw.Object()).WithPayloadReader(r)
	oid, err := n.pool.PutObject(
		ctx,
		ops,
		n.BearerOpt(ctx),
	)
	if err != nil {
		return nil, err
	}

	meta, err := n.objectHead(ctx, bkt.CID, oid)
	if err != nil {
		return nil, err
	}

	if err = n.objCache.Put(addr, *meta); err != nil {
		n.log.Error("couldn't cache an object", zap.Error(err))
	}

	objInfo := &ObjectInfo{
		id: oid,

		Owner:       own,
		Bucket:      p.Bucket,
		Name:        p.Object,
		Size:        p.Size,
		Created:     time.Now(),
		Headers:     p.Header,
		ContentType: r.contentType,
		HashSum:     meta.PayloadChecksum().String(),
	}

	for _, id := range idsToDeleteArr {
		if err = n.objectDelete(ctx, bkt.CID, id); err != nil {
			n.log.Warn("couldn't delete object",
				zap.Stringer("version id", id),
				zap.Error(err))
		}
	}

	return objInfo, nil
}

func (n *layer) headLastVersion(ctx context.Context, bkt *BucketInfo, objectName string) (*ObjectInfo, error) {
	ids, err := n.objectSearch(ctx, &findParams{cid: bkt.CID, val: objectName})
	if err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	}

	infos := make([]*object.Object, 0, len(ids))
	for _, id := range ids {
		meta, err := n.objectHead(ctx, bkt.CID, id)
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", bkt.CID),
				zap.Error(err))
			continue
		}
		infos = append(infos, meta)
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].CreationEpoch() < infos[j].CreationEpoch() || (infos[i].CreationEpoch() == infos[j].CreationEpoch() && infos[i].ID().String() < infos[j].ID().String())
	})

	return objectInfoFromMeta(bkt, infos[len(infos)-1], "", ""), nil
}

func (n *layer) headVersion(ctx context.Context, bkt *BucketInfo, versionID string) (*ObjectInfo, error) {
	oid := object.NewID()
	if err := oid.Parse(versionID); err != nil {
		return nil, err
	}

	meta, err := n.objectHead(ctx, bkt.CID, oid)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
		return nil, err
	}

	return objectInfoFromMeta(bkt, meta, "", ""), nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, cid *cid.ID, oid *object.ID) error {
	address := object.NewAddress()
	address.SetContainerID(cid)
	address.SetObjectID(oid)
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
		allObjects []*ObjectInfo
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
		allObjects []*ObjectInfo
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
		result.NextContinuationToken = allObjects[len(allObjects)-1].id.String()
	}

	result.Prefixes, result.Objects = triageObjects(allObjects)

	return &result, nil
}

func (n *layer) listSortedObjectsFromNeoFS(ctx context.Context, p allObjectParams) ([]*ObjectInfo, error) {
	var (
		err       error
		ids       []*object.ID
		uniqNames = make(map[string]bool)
	)

	if ids, err = n.objectSearch(ctx, &findParams{cid: p.Bucket.CID}); err != nil {
		return nil, err
	}

	objects := make([]*ObjectInfo, 0, len(ids))

	for _, id := range ids {
		meta, err := n.objectHead(ctx, p.Bucket.CID, id)
		if err != nil {
			n.log.Warn("could not fetch object meta", zap.Error(err))
			continue
		}
		if oi := objectInfoFromMeta(p.Bucket, meta, p.Prefix, p.Delimiter); oi != nil {
			// use only unique dir names
			if _, ok := uniqNames[oi.Name]; ok {
				continue
			}

			uniqNames[oi.Name] = oi.isDir

			objects = append(objects, oi)
		}
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	return objects, nil
}

func trimAfterObjectName(startAfter string, objects []*ObjectInfo) []*ObjectInfo {
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

func trimAfterObjectID(id string, objects []*ObjectInfo) []*ObjectInfo {
	if len(objects) != 0 && objects[len(objects)-1].id.String() == id {
		return []*ObjectInfo{}
	}
	for i, obj := range objects {
		if obj.ID().String() == id {
			return objects[i+1:]
		}
	}

	return nil
}

func triageObjects(allObjects []*ObjectInfo) (prefixes []string, objects []*ObjectInfo) {
	for _, ov := range allObjects {
		if ov.isDir {
			prefixes = append(prefixes, ov.Name)
		} else {
			objects = append(objects, ov)
		}
	}

	return
}

func (n *layer) listAllObjects(ctx context.Context, p ListObjectsParamsCommon) ([]*ObjectInfo, error) {
	var (
		err        error
		bkt        *BucketInfo
		cacheKey   cacheOptions
		allObjects []*ObjectInfo
	)

	if bkt, err = n.GetBucketInfo(ctx, p.Bucket); err != nil {
		return nil, err
	}

	if cacheKey, err = createKey(ctx, bkt.CID, p.Prefix, p.Delimiter); err != nil {
		return nil, err
	}

	allObjects = n.listObjCache.Get(cacheKey)

	if allObjects == nil {
		allObjects, err = n.listSortedObjectsFromNeoFS(ctx, allObjectParams{
			Bucket:    bkt,
			Prefix:    p.Prefix,
			Delimiter: p.Delimiter,
		})
		if err != nil {
			return nil, err
		}

		// putting to cache a copy of allObjects because allObjects can be modified further
		n.listObjCache.Put(cacheKey, append([]*ObjectInfo(nil), allObjects...))
	}

	return allObjects, nil
}

func (n *layer) isVersioningEnabled(ctx context.Context, bktInfo *BucketInfo) bool {
	settings, err := n.getBucketSettings(ctx, bktInfo)
	if err != nil {
		n.log.Warn("couldn't get versioning settings object", zap.Error(err))
		return false
	}

	return settings.VersioningEnabled
}
