package layer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/nspcc-dev/neofs-sdk-go/client"
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
		BktInfo   *data.BucketInfo
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

func newAddress(cid cid.ID, oid oid.ID) *address.Address {
	addr := address.NewAddress()
	addr.SetContainerID(cid)
	addr.SetObjectID(oid)
	return addr
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, idCnr *cid.ID, idObj oid.ID) (*object.Object, error) {
	prm := neofs.PrmObjectRead{
		Container:  *idCnr,
		Object:     idObj,
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
	cnrID, _ := addr.ContainerID()
	objID, _ := addr.ObjectID()
	prm := neofs.PrmObjectRead{
		Container:   cnrID,
		Object:      objID,
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

// PutObject stores object into NeoFS, took payload from io.Reader.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error) {
	own := n.Owner(ctx)

	versioningEnabled := n.isVersioningEnabled(ctx, p.BktInfo)
	newVersion := &data.NodeVersion{IsUnversioned: !versioningEnabled}

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
		Container:   *p.BktInfo.CID,
		Creator:     own,
		PayloadSize: uint64(p.Size),
		Filename:    p.Object,
		Payload:     r,
	}

	prm.Attributes = make([][2]string, 0, len(p.Header))

	for k, v := range p.Header {
		prm.Attributes = append(prm.Attributes, [2]string{k, v})
	}

	id, hash, err := n.objectPutAndHash(ctx, prm)
	if err != nil {
		return nil, err
	}

	newVersion.OID = *id
	if err = n.treeService.AddVersion(ctx, p.BktInfo.CID, p.Object, newVersion); err != nil {
		return nil, fmt.Errorf("couldn't add new verion to tree service: %w", err)
	}

	if p.Lock != nil {
		objInfo := &data.ObjectInfo{ID: id, Name: p.Object}
		p.Lock.Objects = append(p.Lock.Objects, *id)
		if p.Lock.LegalHold {
			if err = n.putLockObject(ctx, p.BktInfo, objInfo.LegalHoldObject(), p.Lock); err != nil {
				return nil, err
			}
		}
		if !p.Lock.Until.IsZero() {
			if err = n.putLockObject(ctx, p.BktInfo, objInfo.RetentionObject(), p.Lock); err != nil {
				return nil, err
			}
		}
	}

	n.listsCache.CleanCacheEntriesContainingObject(p.Object, p.BktInfo.CID)

	objInfo := &data.ObjectInfo{
		ID:  id,
		CID: p.BktInfo.CID,

		Owner:       &own,
		Bucket:      p.BktInfo.Name,
		Name:        p.Object,
		Size:        p.Size,
		Created:     time.Now(),
		Headers:     p.Header,
		ContentType: p.Header[api.ContentType],
		HashSum:     hex.EncodeToString(hash),
	}

	if err = n.objCache.PutObject(objInfo); err != nil {
		n.log.Warn("couldn't add object to cache", zap.Error(err),
			zap.String("object_name", p.Object), zap.String("bucket_name", p.BktInfo.Name),
			zap.String("cid", objInfo.CID.EncodeToString()), zap.String("oid", objInfo.ID.EncodeToString()))
	}
	if err = n.namesCache.Put(objInfo.NiceName(), objInfo.Address()); err != nil {
		n.log.Warn("couldn't put obj address to name cache",
			zap.String("obj nice name", objInfo.NiceName()),
			zap.Error(err))
	}

	return objInfo, nil
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

func (n *layer) headLastVersionIfNotDeleted(ctx context.Context, bkt *data.BucketInfo, objectName string) (*data.ObjectInfo, error) {
	if addr := n.namesCache.Get(bkt.Name + "/" + objectName); addr != nil {
		if headInfo := n.objCache.Get(addr); headInfo != nil {
			return objInfoFromMeta(bkt, headInfo), nil
		}
	}

	node, err := n.treeService.GetLatestVersion(ctx, bkt.CID, objectName)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
		}
		return nil, err
	}

	if node.DeleteMarker != nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	}

	meta, err := n.objectHead(ctx, bkt.CID, node.OID)
	if err != nil {
		return nil, err
	}
	if err = n.objCache.Put(*meta); err != nil {
		n.log.Warn("couldn't put meta to objects cache",
			zap.Stringer("object id", node.OID),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}

	objInfo := objInfoFromMeta(bkt, meta)
	if err = n.namesCache.Put(objInfo.NiceName(), objInfo.Address()); err != nil {
		n.log.Warn("couldn't put obj address to head cache",
			zap.String("obj nice name", objInfo.NiceName()),
			zap.Error(err))
	}

	return objInfo, nil
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
		meta, err := n.objectHead(ctx, bkt.CID, ids[i])
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

	versions, err := n.treeService.GetVersions(ctx, bkt.CID, p.Object)
	if err != nil {
		return nil, fmt.Errorf("couldn't get versions: %w", err)
	}

	var foundVersion *data.NodeVersion
	for _, version := range versions {
		if version.OID.String() == p.VersionID {
			foundVersion = version
			break
		}
	}

	if foundVersion == nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
	}

	if headInfo := n.objCache.Get(newAddress(*bkt.CID, foundVersion.OID)); headInfo != nil {
		return objInfoFromMeta(bkt, headInfo), nil
	}

	meta, err := n.objectHead(ctx, bkt.CID, foundVersion.OID)
	if err != nil {
		if client.IsErrObjectNotFound(err) {
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

	n.objCache.Delete(newAddress(*idCnr, *idObj))

	return n.transformNeofsError(ctx, n.neoFS.DeleteObject(ctx, prm))
}

// objectPut prepare auth parameters and invoke neofs.CreateObject.
func (n *layer) objectPut(ctx context.Context, prm neofs.PrmObjectCreate) (*oid.ID, error) {
	n.prepareAuthParameters(ctx, &prm.PrmAuth)

	id, err := n.neoFS.CreateObject(ctx, prm)
	return id, n.transformNeofsError(ctx, err)
}

// objectPutAndHash prepare auth parameters and invoke neofs.CreateObject.
// Returns object ID and payload sha256 hash.
func (n *layer) objectPutAndHash(ctx context.Context, prm neofs.PrmObjectCreate) (*oid.ID, []byte, error) {
	n.prepareAuthParameters(ctx, &prm.PrmAuth)
	hash := sha256.New()
	prm.Payload = wrapReader(prm.Payload, 64*1024, func(buf []byte) {
		hash.Write(buf)
	})
	id, err := n.neoFS.CreateObject(ctx, prm)
	return id, hash.Sum(nil), n.transformNeofsError(ctx, err)
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
	objects, err := n.getLatestObjectsVersions(ctx, p.Bucket, p.Prefix, p.Delimiter)
	if err != nil {
		return nil, err
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	return objects, nil
}

func (n *layer) getLatestObjectsVersions(ctx context.Context, bkt *data.BucketInfo, prefix, delimiter string) ([]*data.ObjectInfo, error) {
	var err error

	cacheKey := cache.CreateObjectsListCacheKey(bkt.CID, prefix, true)
	ids := n.listsCache.Get(cacheKey)

	if ids == nil {
		ids, err = n.treeService.GetLatestVersionsByPrefix(ctx, bkt.CID, prefix)
		if err != nil {
			return nil, err
		}
		if err := n.listsCache.Put(cacheKey, ids); err != nil {
			n.log.Error("couldn't cache list of objects", zap.Error(err))
		}
	}

	objectsMap := make(map[string]*data.ObjectInfo, len(ids)) // to squash the same directories
	for i := 0; i < len(ids); i++ {
		obj := n.objectFromObjectsCacheOrNeoFS(ctx, bkt.CID, &ids[i])
		if obj == nil {
			continue
		}
		if oi := objectInfoFromMeta(bkt, obj, prefix, delimiter); oi != nil {
			if isSystem(oi) {
				continue
			}

			objectsMap[oi.Name] = oi
		}
	}

	objects := make([]*data.ObjectInfo, 0, len(objectsMap))
	for _, obj := range objectsMap {
		objects = append(objects, obj)
	}

	return objects, nil
}

func (n *layer) getAllObjectsVersions(ctx context.Context, bkt *data.BucketInfo, prefix, delimiter string) (map[string][]*data.ExtendedObjectInfo, error) {
	var err error

	cacheKey := cache.CreateObjectsListCacheKey(bkt.CID, prefix, false)
	nodeVersions := n.listsCache.GetVersions(cacheKey)

	if nodeVersions == nil {
		nodeVersions, err = n.treeService.GetAllVersionsByPrefix(ctx, bkt.CID, prefix)
		if err != nil {
			return nil, err
		}
		if err = n.listsCache.PutVersions(cacheKey, nodeVersions); err != nil {
			n.log.Error("couldn't cache list of objects", zap.Error(err))
		}
	}

	versions := make(map[string][]*data.ExtendedObjectInfo, len(nodeVersions))

	for _, nodeVersion := range nodeVersions {
		oi := &data.ObjectInfo{}

		if nodeVersion.DeleteMarker != nil { // delete marker does not match any object in NeoFS
			oi.ID = &nodeVersion.OID
			oi.Name = nodeVersion.DeleteMarker.FilePath
			oi.Owner = &nodeVersion.DeleteMarker.Owner
			oi.Created = nodeVersion.DeleteMarker.Created
			oi.IsDeleteMarker = true
		} else {
			obj := n.objectFromObjectsCacheOrNeoFS(ctx, bkt.CID, &nodeVersion.OID)
			if obj == nil {
				continue
			}
			oi = objectInfoFromMeta(bkt, obj, prefix, delimiter)
			if oi == nil {
				continue
			}
		}

		eoi := &data.ExtendedObjectInfo{
			ObjectInfo:  oi,
			NodeVersion: nodeVersion,
		}

		objVersions, ok := versions[oi.Name]
		if !ok {
			objVersions = []*data.ExtendedObjectInfo{eoi}
		} else if !oi.IsDir {
			objVersions = append(objVersions, eoi)
		}
		versions[oi.Name] = objVersions
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
		allObjects []*data.ObjectInfo
	)

	allObjects, err = n.listSortedObjects(ctx, allObjectParams{
		Bucket:    p.BktInfo,
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
		meta = n.objCache.Get(newAddress(*cid, *oid))
	)
	if meta == nil {
		meta, err = n.objectHead(ctx, cid, *oid)
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

func wrapReader(input io.Reader, bufSize int, f func(buf []byte)) io.Reader {
	r, w := io.Pipe()
	go func() {
		var buf = make([]byte, bufSize)
		for {
			n, err := input.Read(buf)
			if n > 0 {
				f(buf[:n])
				_, _ = w.Write(buf[:n]) // ignore error, input is not ReadCloser
			}
			if err != nil {
				_ = w.CloseWithError(err)
				break
			}
		}
	}()
	return r
}
