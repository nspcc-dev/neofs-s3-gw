package layer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

type (
	getParams struct {
		// payload range
		off, ln uint64

		oid     oid.ID
		bktInfo *data.BucketInfo
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
		Bucket            *data.BucketInfo
		Delimiter         string
		Prefix            string
		MaxKeys           int
		Marker            string
		ContinuationToken string
	}
)

const (
	continuationToken = "<continuation-token>"
)

func newAddress(cnr cid.ID, obj oid.ID) oid.Address {
	var addr oid.Address
	addr.SetContainer(cnr)
	addr.SetObject(obj)
	return addr
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) (*object.Object, error) {
	prm := PrmObjectRead{
		Container:  bktInfo.CID,
		Object:     idObj,
		WithHeader: true,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	return res.Head, nil
}

// initializes payload reader of the NeoFS object.
// Zero range corresponds to full payload (panics if only offset is set).
func (n *layer) initObjectPayloadReader(ctx context.Context, p getParams) (io.Reader, error) {
	prm := PrmObjectRead{
		Container:    p.bktInfo.CID,
		Object:       p.oid,
		WithPayload:  true,
		PayloadRange: [2]uint64{p.off, p.ln},
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, p.bktInfo.Owner)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	return res.Payload, nil
}

// objectGet returns an object with payload in the object.
func (n *layer) objectGet(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (*object.Object, error) {
	prm := PrmObjectRead{
		Container:   bktInfo.CID,
		Object:      objID,
		WithHeader:  true,
		WithPayload: true,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	return res.Head, nil
}

// MimeByFileName detect mime type by filename extension.
func MimeByFileName(name string) string {
	ext := filepath.Ext(name)
	if len(ext) == 0 {
		return ""
	}
	return mime.TypeByExtension(ext)
}

// PutObject stores object into NeoFS, took payload from io.Reader.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error) {
	own := n.Owner(ctx)

	versioningEnabled := n.isVersioningEnabled(ctx, p.BktInfo)
	newVersion := &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{FilePath: p.Object},
		IsUnversioned:   !versioningEnabled,
	}

	r := p.Reader
	if r != nil {
		if len(p.Header[api.ContentType]) == 0 {
			if contentType := MimeByFileName(p.Object); len(contentType) == 0 {
				d := newDetector(r)
				if contentType, err := d.Detect(); err == nil {
					p.Header[api.ContentType] = contentType
				}
				r = d.MultiReader()
			} else {
				p.Header[api.ContentType] = contentType
			}
		}
	}

	prm := PrmObjectCreate{
		Container:   p.BktInfo.CID,
		Creator:     own,
		PayloadSize: uint64(p.Size),
		Filename:    p.Object,
		Payload:     r,
	}

	prm.Attributes = make([][2]string, 0, len(p.Header))

	for k, v := range p.Header {
		prm.Attributes = append(prm.Attributes, [2]string{k, v})
	}

	id, hash, err := n.objectPutAndHash(ctx, prm, p.BktInfo)
	if err != nil {
		return nil, err
	}

	newVersion.OID = *id
	if err = n.treeService.AddVersion(ctx, p.BktInfo.CID, newVersion); err != nil {
		return nil, fmt.Errorf("couldn't add new verion to tree service: %w", err)
	}

	if p.Lock != nil && (p.Lock.Retention != nil || p.Lock.LegalHold != nil) {
		objVersion := &ObjectVersion{
			BktInfo:    p.BktInfo,
			ObjectName: p.Object,
			VersionID:  id.EncodeToString(),
		}

		if err = n.PutLockInfo(ctx, objVersion, p.Lock); err != nil {
			return nil, err
		}
	}

	n.listsCache.CleanCacheEntriesContainingObject(p.Object, p.BktInfo.CID)

	objInfo := &data.ObjectInfo{
		ID:  *id,
		CID: p.BktInfo.CID,

		Owner:       own,
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

func (n *layer) headLastVersionIfNotDeleted(ctx context.Context, bkt *data.BucketInfo, objectName string) (*data.ObjectInfo, error) {
	if addr := n.namesCache.Get(bkt.Name + "/" + objectName); addr != nil {
		if objInfo := n.objCache.GetObject(*addr); objInfo != nil {
			return objInfo, nil
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

	meta, err := n.objectHead(ctx, bkt, node.OID)
	if err != nil {
		return nil, err
	}
	objInfo := objInfoFromMeta(bkt, meta)
	if err = n.objCache.PutObject(objInfo); err != nil {
		n.log.Warn("couldn't put object info to cache",
			zap.Stringer("object id", node.OID),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}
	if err = n.namesCache.Put(objInfo.NiceName(), objInfo.Address()); err != nil {
		n.log.Warn("couldn't put obj address to head cache",
			zap.String("obj nice name", objInfo.NiceName()),
			zap.Error(err))
	}

	return objInfo, nil
}

func (n *layer) headVersion(ctx context.Context, bkt *data.BucketInfo, p *HeadObjectParams) (*data.ObjectInfo, error) {
	var err error
	var foundVersion *data.NodeVersion
	if p.VersionID == UnversionedObjectVersionID {
		foundVersion, err = n.treeService.GetUnversioned(ctx, bkt.CID, p.Object)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
			}
			return nil, err
		}
	} else {
		versions, err := n.treeService.GetVersions(ctx, bkt.CID, p.Object)
		if err != nil {
			return nil, fmt.Errorf("couldn't get versions: %w", err)
		}

		for _, version := range versions {
			if version.OID.EncodeToString() == p.VersionID {
				foundVersion = version
				break
			}
		}
		if foundVersion == nil {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
	}

	if objInfo := n.objCache.GetObject(newAddress(bkt.CID, foundVersion.OID)); objInfo != nil {
		return objInfo, nil
	}

	meta, err := n.objectHead(ctx, bkt, foundVersion.OID)
	if err != nil {
		if client.IsErrObjectNotFound(err) {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
		return nil, err
	}

	objInfo := objInfoFromMeta(bkt, meta)
	if err = n.objCache.PutObject(objInfo); err != nil {
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
func (n *layer) objectDelete(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) error {
	prm := PrmObjectDelete{
		Container: bktInfo.CID,
		Object:    idObj,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	n.objCache.Delete(newAddress(bktInfo.CID, idObj))

	return n.transformNeofsError(ctx, n.neoFS.DeleteObject(ctx, prm))
}

// objectPutAndHash prepare auth parameters and invoke neofs.CreateObject.
// Returns object ID and payload sha256 hash.
func (n *layer) objectPutAndHash(ctx context.Context, prm PrmObjectCreate, bktInfo *data.BucketInfo) (*oid.ID, []byte, error) {
	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)
	hash := sha256.New()
	prm.Payload = wrapReader(prm.Payload, 64*1024, func(buf []byte) {
		hash.Write(buf)
	})
	id, err := n.neoFS.CreateObject(ctx, prm)
	return id, hash.Sum(nil), n.transformNeofsError(ctx, err)
}

// ListObjectsV1 returns objects in a bucket for requests of Version 1.
func (n *layer) ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error) {
	var result ListObjectsInfoV1

	prm := allObjectParams{
		Bucket:    p.BktInfo,
		Delimiter: p.Delimiter,
		Prefix:    p.Prefix,
		MaxKeys:   p.MaxKeys,
		Marker:    p.Marker,
	}

	objects, next, err := n.getLatestObjectsVersions(ctx, prm)
	if err != nil {
		return nil, err
	}

	if next != nil {
		result.IsTruncated = true
		result.NextMarker = objects[len(objects)-1].Name
	}

	result.Prefixes, result.Objects = triageObjects(objects)

	return &result, nil
}

// ListObjectsV2 returns objects in a bucket for requests of Version 2.
func (n *layer) ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error) {
	var result ListObjectsInfoV2

	prm := allObjectParams{
		Bucket:            p.BktInfo,
		Delimiter:         p.Delimiter,
		Prefix:            p.Prefix,
		MaxKeys:           p.MaxKeys,
		Marker:            p.StartAfter,
		ContinuationToken: p.ContinuationToken,
	}

	objects, next, err := n.getLatestObjectsVersions(ctx, prm)
	if err != nil {
		return nil, err
	}

	if next != nil {
		result.IsTruncated = true
		result.NextContinuationToken = next.ID.EncodeToString()
	}

	result.Prefixes, result.Objects = triageObjects(objects)

	return &result, nil
}

type logWrapper struct {
	log *zap.Logger
}

func (l *logWrapper) Printf(format string, args ...interface{}) {
	l.log.Info(fmt.Sprintf(format, args...))
}

func (n *layer) getLatestObjectsVersions(ctx context.Context, p allObjectParams) (objects []*data.ObjectInfo, next *data.ObjectInfo, err error) {
	if p.MaxKeys == 0 {
		return nil, nil, nil
	}

	cacheKey := cache.CreateObjectsListCacheKey(p.Bucket.CID, p.Prefix, true)
	nodeVersions := n.listsCache.GetVersions(cacheKey)

	if nodeVersions == nil {
		nodeVersions, err = n.treeService.GetLatestVersionsByPrefix(ctx, p.Bucket.CID, p.Prefix)
		if err != nil {
			return nil, nil, err
		}
		if err = n.listsCache.PutVersions(cacheKey, nodeVersions); err != nil {
			n.log.Error("couldn't cache list of objects", zap.Error(err))
		}
	}

	if len(nodeVersions) == 0 {
		return nil, nil, nil
	}

	sort.Slice(nodeVersions, func(i, j int) bool {
		return nodeVersions[i].FilePath < nodeVersions[j].FilePath
	})

	poolCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	objOutCh, err := n.initWorkerPool(poolCtx, 2, p, nodesGenerator(poolCtx, p, nodeVersions))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init worker pool: %w", err)
	}

	objects = make([]*data.ObjectInfo, 0, p.MaxKeys)

	for obj := range objOutCh {
		if len(objects) == p.MaxKeys { // todo reconsider stop condition
			next = obj
			break
		}
		objects = append(objects, obj)
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	return
}

func nodesGenerator(ctx context.Context, p allObjectParams, nodeVersions []*data.NodeVersion) <-chan *data.NodeVersion {
	nodeCh := make(chan *data.NodeVersion)
	existed := make(map[string]struct{}, len(nodeVersions)) // to squash the same directories

	go func() {
	LOOP:
		for _, node := range nodeVersions {
			if shouldSkip(node, p, existed) {
				continue
			}

			select {
			case <-ctx.Done():
				break LOOP
			case nodeCh <- node:
			}
		}
		close(nodeCh)
	}()

	return nodeCh
}

func (n *layer) initWorkerPool(ctx context.Context, size int, p allObjectParams, input <-chan *data.NodeVersion) (<-chan *data.ObjectInfo, error) {
	pool, err := ants.NewPool(size, ants.WithLogger(&logWrapper{n.log}))
	if err != nil {
		return nil, fmt.Errorf("coudln't init go pool for listing: %w", err)
	}
	objCh := make(chan *data.ObjectInfo)

	go func() {
		var wg sync.WaitGroup

	LOOP:
		for node := range input {
			select {
			case <-ctx.Done():
				break LOOP
			default:
			}

			// We have to make a copy of pointer to data.NodeVersion
			// to get correct value in submitted task function.
			func(node *data.NodeVersion) {
				wg.Add(1)
				err = pool.Submit(func() {
					defer wg.Done()
					if oi := n.objectInfoFromObjectsCacheOrNeoFS(ctx, p.Bucket, node.OID, p.Prefix, p.Delimiter); oi != nil {
						select {
						case <-ctx.Done():
						case objCh <- oi:
						}
					}
				})
				if err != nil {
					wg.Done()
					n.log.Warn("failed to submit task to pool", zap.Error(err))
				}
			}(node)
		}
		wg.Wait()
		close(objCh)
		pool.Release()
	}()

	return objCh, nil
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
			oi.ID = nodeVersion.OID
			oi.Name = nodeVersion.FilePath
			oi.Owner = nodeVersion.DeleteMarker.Owner
			oi.Created = nodeVersion.DeleteMarker.Created
			oi.IsDeleteMarker = true
		} else {
			if oi = n.objectInfoFromObjectsCacheOrNeoFS(ctx, bkt, nodeVersion.OID, prefix, delimiter); oi == nil {
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

func IsSystemHeader(key string) bool {
	return strings.HasPrefix(key, "S3-")
}

func shouldSkip(node *data.NodeVersion, p allObjectParams, existed map[string]struct{}) bool {
	filepath := node.FilePath
	if len(p.Delimiter) > 0 {
		tail := strings.TrimPrefix(filepath, p.Prefix)
		index := strings.Index(tail, p.Delimiter)
		if index >= 0 {
			filepath = p.Prefix + tail[:index+1]
		}
	}
	if _, ok := existed[filepath]; ok {
		return true
	}

	if filepath <= p.Marker {
		return true
	}

	if p.ContinuationToken != "" {
		if _, ok := existed[continuationToken]; !ok {
			if p.ContinuationToken != node.OID.EncodeToString() {
				return true
			}
			existed[continuationToken] = struct{}{}
		}
	}

	existed[filepath] = struct{}{}
	return false
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

func triageExtendedObjects(allObjects []*data.ExtendedObjectInfo) (prefixes []string, objects []*data.ExtendedObjectInfo) {
	for _, ov := range allObjects {
		if ov.ObjectInfo.IsDir {
			prefixes = append(prefixes, ov.ObjectInfo.Name)
		} else {
			objects = append(objects, ov)
		}
	}

	return
}

func (n *layer) isVersioningEnabled(ctx context.Context, bktInfo *data.BucketInfo) bool {
	settings, err := n.GetBucketSettings(ctx, bktInfo)
	if err != nil {
		n.log.Warn("couldn't get versioning settings object", zap.Error(err))
		return false
	}

	return settings.VersioningEnabled
}

func (n *layer) objectInfoFromObjectsCacheOrNeoFS(ctx context.Context, bktInfo *data.BucketInfo, obj oid.ID, prefix, delimiter string) *data.ObjectInfo {
	if objInfo := n.objCache.GetObject(newAddress(bktInfo.CID, obj)); objInfo != nil {
		return objInfo
	}

	meta, err := n.objectHead(ctx, bktInfo, obj)
	if err != nil {
		n.log.Warn("could not fetch object meta", zap.Error(err))
		return nil
	}

	objInfo := objectInfoFromMeta(bktInfo, meta, prefix, delimiter)
	if err = n.objCache.PutObject(objInfo); err != nil {
		n.log.Warn("couldn't cache an object", zap.Error(err))
	}

	return objInfo
}

func (n *layer) transformNeofsError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, ErrAccessDenied) {
		n.log.Debug("error was transformed", zap.String("request_id", api.GetRequestID(ctx)), zap.Error(err))
		return apiErrors.GetAPIError(apiErrors.ErrAccessDenied)
	}

	return err
}

func wrapReader(input io.Reader, bufSize int, f func(buf []byte)) io.Reader {
	if input == nil {
		return nil
	}

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
