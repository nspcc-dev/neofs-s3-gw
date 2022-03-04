package layer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

type (
	findParams struct {
		attr   [2]string
		cid    *cid.ID
		prefix string
	}

	getParams struct {
		// payload range
		off, ln uint64

		cid *cid.ID
		oid *oid.ID
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
		Bucket    *data.BucketInfo
		Delimiter string
		Prefix    string
	}
)

func (n *layer) objectSearchByName(ctx context.Context, cid *cid.ID, filename string) ([]oid.ID, error) {
	f := &findParams{
		attr: [2]string{object.AttributeFileName, filename},
		cid:  cid,
	}
	return n.objectSearch(ctx, f)
}

// objectSearch returns all available objects by search params.
func (n *layer) objectSearch(ctx context.Context, p *findParams) ([]oid.ID, error) {
	prm := neofs.PrmObjectSelect{
		Container:      *p.cid,
		ExactAttribute: p.attr,
		FilePrefix:     p.prefix,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	res, err := n.neoFS.SelectObjects(ctx, prm)

	return res, n.transformNeofsError(ctx, err)
}

func newAddress(cid *cid.ID, oid *oid.ID) *address.Address {
	addr := address.NewAddress()
	addr.SetContainerID(cid)
	addr.SetObjectID(oid)
	return addr
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, idCnr *cid.ID, idObj *oid.ID) (*object.Object, error) {
	prm := neofs.PrmObjectRead{
		Container:  *idCnr,
		Object:     *idObj,
		WithHeader: true,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	return res.Head, nil
}

// initializes payload reader of the NeoFS object.
// Zero range corresponds to full payload (panics if only offset is set).
func (n *layer) initObjectPayloadReader(ctx context.Context, p getParams) (io.Reader, error) {
	prm := neofs.PrmObjectRead{
		Container:    *p.cid,
		Object:       *p.oid,
		WithPayload:  true,
		PayloadRange: [2]uint64{p.off, p.ln},
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	return res.Payload, nil
}

// objectGet returns an object with payload in the object.
func (n *layer) objectGet(ctx context.Context, addr *address.Address) (*object.Object, error) {
	prm := neofs.PrmObjectRead{
		Container:   *addr.ContainerID(),
		Object:      *addr.ObjectID(),
		WithHeader:  true,
		WithPayload: true,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	return res.Head, nil
}

// objectPut into NeoFS, took payload from io.Reader.
func (n *layer) objectPut(ctx context.Context, bkt *data.BucketInfo, p *PutObjectParams) (*data.ObjectInfo, error) {
	own := n.Owner(ctx)

	versioningEnabled := n.isVersioningEnabled(ctx, bkt)
	versions, err := n.headVersions(ctx, bkt, p.Object)
	if err != nil && !apiErrors.IsS3Error(err, apiErrors.ErrNoSuchKey) {
		return nil, err
	}
	idsToDeleteArr := updateCRDT2PSetHeaders(p.Header, versions, versioningEnabled)

	r := p.Reader
	if r != nil {
		if len(p.Header[api.ContentType]) == 0 {
			d := newDetector(r)
			if contentType, err := d.Detect(); err == nil {
				p.Header[api.ContentType] = contentType
			}
			r = d.MultiReader()
		}
	}

	prm := neofs.PrmObjectCreate{
		Container:   *bkt.CID,
		Creator:     *own,
		PayloadSize: uint64(p.Size),
		Filename:    p.Object,
		Payload:     r,
	}

	prm.Attributes = make([][2]string, 0, len(p.Header))

	for k, v := range p.Header {
		prm.Attributes = append(prm.Attributes, [2]string{k, v})
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	if p.Header[VersionsDeleteMarkAttr] == DelMarkFullObject {
		if last := versions.getLast(); last != nil {
			n.objCache.Delete(last.Address())
		}
	}

	id, err := n.neoFS.CreateObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	if p.Lock != nil {
		objInfo := &data.ObjectInfo{ID: id, Name: p.Object}
		p.Lock.Objects = append(p.Lock.Objects, *id)
		if p.Lock.LegalHold {
			if err = n.putLockObject(ctx, bkt, objInfo.LegalHoldObject(), p.Lock); err != nil {
				return nil, err
			}
		}
		if !p.Lock.Until.IsZero() {
			if err = n.putLockObject(ctx, bkt, objInfo.RetentionObject(), p.Lock); err != nil {
				return nil, err
			}
		}
	}

	meta, err := n.objectHead(ctx, bkt.CID, id)
	if err != nil {
		return nil, err
	}

	if err = n.objCache.Put(*meta); err != nil {
		n.log.Error("couldn't cache an object", zap.Error(err))
	}

	n.listsCache.CleanCacheEntriesContainingObject(p.Object, bkt.CID)

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

	return &data.ObjectInfo{
		ID:  id,
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

func (n *layer) putLockObject(ctx context.Context, bktInfo *data.BucketInfo, objName string, lock *data.ObjectLock) error {
	ps := &PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  objName,
		Lock:     lock,
		Metadata: make(map[string]string),
	}

	if _, err := n.PutSystemObject(ctx, ps); err != nil {
		return fmt.Errorf("coudln't add lock for '%s': %w", objName, err)
	}

	return nil
}

func updateCRDT2PSetHeaders(header map[string]string, versions *objectVersions, versioningEnabled bool) []*oid.ID {
	if !versioningEnabled {
		header[versionsUnversionedAttr] = "true"
	}

	var idsToDeleteArr []*oid.ID
	if versions.isEmpty() {
		return idsToDeleteArr
	}

	if !versions.isAddListEmpty() {
		header[versionsAddAttr] = versions.getAddHeader()
	}

	if versioningEnabled {
		versionsDeletedStr := versions.getDelHeader()
		// header[versionsDelAttr] can be not empty when deleting specific version
		if delAttr := header[versionsDelAttr]; len(delAttr) != 0 {
			if len(versionsDeletedStr) != 0 {
				header[versionsDelAttr] = versionsDeletedStr + "," + delAttr
			} else {
				header[versionsDelAttr] = delAttr
			}
		} else if len(versionsDeletedStr) != 0 {
			header[versionsDelAttr] = versionsDeletedStr
		}
	} else {
		versionsDeletedStr := versions.getDelHeader()

		var additionalDel string
		for i, del := range versions.unversioned() {
			if i != 0 {
				additionalDel += ","
			}
			additionalDel += del.Version()
			idsToDeleteArr = append(idsToDeleteArr, del.ID)
		}

		if len(additionalDel) != 0 {
			if len(versionsDeletedStr) != 0 {
				versionsDeletedStr += ","
			}
			versionsDeletedStr += additionalDel
		}

		if len(versionsDeletedStr) != 0 {
			header[versionsDelAttr] = versionsDeletedStr
		}
	}

	return idsToDeleteArr
}

func (n *layer) headLastVersionIfNotDeleted(ctx context.Context, bkt *data.BucketInfo, objectName string) (*data.ObjectInfo, error) {
	if addr := n.namesCache.Get(bkt.Name + "/" + objectName); addr != nil {
		if headInfo := n.objCache.Get(addr); headInfo != nil {
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

func (n *layer) headVersions(ctx context.Context, bkt *data.BucketInfo, objectName string) (*objectVersions, error) {
	ids, err := n.objectSearchByName(ctx, bkt.CID, objectName)
	if err != nil {
		return nil, err
	}

	versions := newObjectVersions(objectName)
	if len(ids) == 0 {
		return versions, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	}

	for i := range ids {
		meta, err := n.objectHead(ctx, bkt.CID, &ids[i])
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", &ids[i]),
				zap.Stringer("bucket id", bkt.CID),
				zap.Error(err))
			continue
		}
		if err = n.objCache.Put(*meta); err != nil {
			n.log.Warn("couldn't put meta to objects cache",
				zap.Stringer("object id", &ids[i]),
				zap.Stringer("bucket id", bkt.CID),
				zap.Error(err))
		}

		if oi := objInfoFromMeta(bkt, meta); oi != nil {
			if isSystem(oi) {
				continue
			}
			versions.appendVersion(oi)
		}
	}

	return versions, nil
}

func (n *layer) headVersion(ctx context.Context, bkt *data.BucketInfo, p *HeadObjectParams) (*data.ObjectInfo, error) {
	if p.VersionID == unversionedObjectVersionID {
		versions, err := n.headVersions(ctx, bkt, p.Object)
		if err != nil {
			return nil, err
		}

		objInfo := versions.getLast(FromUnversioned())
		if objInfo == nil {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
		return objInfo, nil
	}

	id := oid.NewID()
	if err := id.Parse(p.VersionID); err != nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrInvalidVersion)
	}

	if headInfo := n.objCache.Get(newAddress(bkt.CID, id)); headInfo != nil {
		return objInfoFromMeta(bkt, headInfo), nil
	}

	meta, err := n.objectHead(ctx, bkt.CID, id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
		return nil, err
	}

	objInfo := objInfoFromMeta(bkt, meta)
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
func (n *layer) objectDelete(ctx context.Context, idCnr *cid.ID, idObj *oid.ID) error {
	prm := neofs.PrmObjectDelete{
		Container: *idCnr,
		Object:    *idObj,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	n.objCache.Delete(newAddress(idCnr, idObj))

	return n.transformNeofsError(ctx, n.neoFS.DeleteObject(ctx, prm))
}

// ListObjectsV1 returns objects in a bucket for requests of Version 1.
func (n *layer) ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error) {
	var (
		err        error
		result     ListObjectsInfoV1
		allObjects []*data.ObjectInfo
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
		allObjects []*data.ObjectInfo
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

func (n *layer) listSortedObjects(ctx context.Context, p allObjectParams) ([]*data.ObjectInfo, error) {
	versions, err := n.getAllObjectsVersions(ctx, p.Bucket, p.Prefix, p.Delimiter)
	if err != nil {
		return nil, err
	}

	objects := make([]*data.ObjectInfo, 0, len(versions))
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

func (n *layer) getAllObjectsVersions(ctx context.Context, bkt *data.BucketInfo, prefix, delimiter string) (map[string]*objectVersions, error) {
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
		obj := n.objectFromObjectsCacheOrNeoFS(ctx, bkt.CID, &ids[i])
		if obj == nil {
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

func splitVersions(header string) []string {
	if len(header) == 0 {
		return nil
	}

	return strings.Split(header, ",")
}

func isSystem(obj *data.ObjectInfo) bool {
	return len(obj.Headers[objectSystemAttributeName]) > 0 ||
		len(obj.Headers[attrVersionsIgnore]) > 0
}

func IsSystemHeader(key string) bool {
	return strings.HasPrefix(key, "S3-")
}

func trimAfterObjectName(startAfter string, objects []*data.ObjectInfo) []*data.ObjectInfo {
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

func trimAfterObjectID(id string, objects []*data.ObjectInfo) []*data.ObjectInfo {
	if len(objects) != 0 && objects[len(objects)-1].ID.String() == id {
		return []*data.ObjectInfo{}
	}
	for i, obj := range objects {
		if obj.ID.String() == id {
			return objects[i+1:]
		}
	}

	return nil
}

func triageObjects(allObjects []*data.ObjectInfo) (prefixes []string, objects []*data.ObjectInfo) {
	for _, ov := range allObjects {
		if ov.IsDir {
			prefixes = append(prefixes, ov.Name)
		} else {
			objects = append(objects, ov)
		}
	}

	return
}

func (n *layer) listAllObjects(ctx context.Context, p ListObjectsParamsCommon) ([]*data.ObjectInfo, error) {
	var (
		err        error
		bkt        *data.BucketInfo
		allObjects []*data.ObjectInfo
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

func (n *layer) isVersioningEnabled(ctx context.Context, bktInfo *data.BucketInfo) bool {
	settings, err := n.GetBucketSettings(ctx, bktInfo)
	if err != nil {
		n.log.Warn("couldn't get versioning settings object", zap.Error(err))
		return false
	}

	return settings.VersioningEnabled
}

func (n *layer) objectFromObjectsCacheOrNeoFS(ctx context.Context, cid *cid.ID, oid *oid.ID) *object.Object {
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

func (n *layer) transformNeofsError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, neofs.ErrAccessDenied) {
		n.log.Debug("error was transformed", zap.String("request_id", api.GetRequestID(ctx)), zap.Error(err))
		return apiErrors.GetAPIError(apiErrors.ErrAccessDenied)
	}

	return err
}
