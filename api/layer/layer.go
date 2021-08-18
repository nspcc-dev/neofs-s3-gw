package layer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/netmap"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"go.uber.org/zap"
)

type (
	layer struct {
		pool        pool.Pool
		log         *zap.Logger
		listsCache  ObjectsListCache
		objCache    cache.ObjectsCache
		headCache   cache.HeadObjectsCache
		bucketCache cache.BucketCache
		systemCache cache.SystemCache
	}

	// CacheConfig contains params for caches.
	CacheConfig struct {
		Lifetime            time.Duration
		Size                int
		ListObjectsLifetime time.Duration
	}

	// Params stores basic API parameters.
	Params struct {
		Pool    pool.Pool
		Logger  *zap.Logger
		Timeout time.Duration
		Key     *ecdsa.PrivateKey
	}

	// GetObjectParams stores object get request parameters.
	GetObjectParams struct {
		Range      *RangeParams
		ObjectInfo *ObjectInfo
		//Bucket    string
		//Object    string
		Offset    int64
		Length    int64
		Writer    io.Writer
		VersionID string
	}

	// HeadObjectParams stores object head request parameters.
	HeadObjectParams struct {
		Bucket    string
		Object    string
		VersionID string
	}

	// RangeParams stores range header request parameters.
	RangeParams struct {
		Start uint64
		End   uint64
	}

	// PutObjectParams stores object put request parameters.
	PutObjectParams struct {
		Bucket string
		Object string
		Size   int64
		Reader io.Reader
		Header map[string]string
	}

	// PutVersioningParams stores object copy request parameters.
	PutVersioningParams struct {
		Bucket   string
		Settings *BucketSettings
	}

	// BucketSettings stores settings such as versioning.
	BucketSettings struct {
		VersioningEnabled bool
	}

	// CopyObjectParams stores object copy request parameters.
	CopyObjectParams struct {
		SrcObject *ObjectInfo
		DstBucket string
		DstObject string
		SrcSize   int64
		Header    map[string]string
	}
	// CreateBucketParams stores bucket create request parameters.
	CreateBucketParams struct {
		Name    string
		ACL     uint32
		Policy  *netmap.PlacementPolicy
		EACL    *eacl.Table
		BoxData *accessbox.Box
	}
	// PutBucketACLParams stores put bucket acl request parameters.
	PutBucketACLParams struct {
		Name string
		EACL *eacl.Table
	}
	// DeleteBucketParams stores delete bucket request parameters.
	DeleteBucketParams struct {
		Name string
	}
	// ListObjectVersionsParams stores list objects versions parameters.
	ListObjectVersionsParams struct {
		Bucket          string
		Delimiter       string
		KeyMarker       string
		MaxKeys         int
		Prefix          string
		VersionIDMarker string
		Encode          string
	}

	// VersionedObject stores object name and version.
	VersionedObject struct {
		Name      string
		VersionID string
	}

	objectVersions struct {
		name     string
		objects  []*ObjectInfo
		addList  []string
		delList  []string
		isSorted bool
	}

	// NeoFS provides basic NeoFS interface.
	NeoFS interface {
		Get(ctx context.Context, address *object.Address) (*object.Object, error)
	}

	// Client provides S3 API client interface.
	Client interface {
		NeoFS

		PutBucketVersioning(ctx context.Context, p *PutVersioningParams) (*ObjectInfo, error)
		GetBucketVersioning(ctx context.Context, name string) (*BucketSettings, error)

		ListBuckets(ctx context.Context) ([]*cache.BucketInfo, error)
		GetBucketInfo(ctx context.Context, name string) (*cache.BucketInfo, error)
		GetBucketACL(ctx context.Context, name string) (*BucketACL, error)
		PutBucketACL(ctx context.Context, p *PutBucketACLParams) error
		CreateBucket(ctx context.Context, p *CreateBucketParams) (*cid.ID, error)
		DeleteBucket(ctx context.Context, p *DeleteBucketParams) error

		GetObject(ctx context.Context, p *GetObjectParams) error
		GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*ObjectInfo, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, bucket string, objects []*VersionedObject) []error
	}
)

func newObjectVersions(name string) *objectVersions {
	return &objectVersions{name: name}
}

func (v *objectVersions) appendVersion(oi *ObjectInfo) {
	addVers := append(splitVersions(oi.Headers[versionsAddAttr]), oi.Version())
	delVers := splitVersions(oi.Headers[versionsDelAttr])
	v.objects = append(v.objects, oi)
	for _, add := range addVers {
		if !contains(v.addList, add) {
			v.addList = append(v.addList, add)
		}
	}
	for _, del := range delVers {
		if !contains(v.delList, del) {
			v.delList = append(v.delList, del)
		}
	}
	v.isSorted = false
}

func (v *objectVersions) sort() {
	if !v.isSorted {
		sortVersions(v.objects)
		v.isSorted = true
	}
}

func (v *objectVersions) getLast() *ObjectInfo {
	if len(v.objects) == 0 {
		return nil
	}

	v.sort()
	existedVersions := getExistedVersions(v)
	for i := len(v.objects) - 1; i >= 0; i-- {
		if contains(existedVersions, v.objects[i].Version()) {
			delMarkHeader := v.objects[i].Headers[versionsDeleteMarkAttr]
			if delMarkHeader == "" {
				return v.objects[i]
			}
			if delMarkHeader == delMarkFullObject {
				return nil
			}
		}
	}

	return nil
}

func (v *objectVersions) getFiltered() []*ObjectInfo {
	if len(v.objects) == 0 {
		return nil
	}

	v.sort()
	existedVersions := getExistedVersions(v)
	res := make([]*ObjectInfo, 0, len(v.objects))

	for _, version := range v.objects {
		delMark := version.Headers[versionsDeleteMarkAttr]
		if contains(existedVersions, version.Version()) && (delMark == delMarkFullObject || delMark == "") {
			res = append(res, version)
		}
	}

	return res
}

func (v *objectVersions) getAddHeader() string {
	return strings.Join(v.addList, ",")
}

func (v *objectVersions) getDelHeader() string {
	return strings.Join(v.delList, ",")
}

const (
	unversionedObjectVersionID    = "null"
	bktVersionSettingsObject      = ".s3-versioning-settings"
	objectSystemAttributeName     = "S3-System-name"
	attrVersionsIgnore            = "S3-Versions-ignore"
	attrSettingsVersioningEnabled = "S3-Settings-Versioning-enabled"
	versionsDelAttr               = "S3-Versions-del"
	versionsAddAttr               = "S3-Versions-add"
	versionsDeleteMarkAttr        = "S3-Versions-delete-mark"
	delMarkFullObject             = "*"
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

// NewLayer creates instance of layer. It checks credentials
// and establishes gRPC connection with node.
func NewLayer(log *zap.Logger, conns pool.Pool, config *CacheConfig) Client {
	return &layer{
		pool:       conns,
		log:        log,
		listsCache: newListObjectsCache(config.ListObjectsLifetime),
		objCache:   cache.New(config.Size, config.Lifetime),
		//todo reconsider cache params
		headCache:   cache.NewHeadObject(1000, time.Minute),
		bucketCache: cache.NewBucketCache(150, time.Minute),
		systemCache: cache.NewSystemCache(1000, 5*time.Minute),
	}
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (n *layer) Owner(ctx context.Context) *owner.ID {
	if data, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && data != nil && data.Gate != nil {
		return data.Gate.BearerToken.Issuer()
	}

	return n.pool.OwnerID()
}

// BearerOpt returns client.WithBearer call option with token from context or with nil token.
func (n *layer) BearerOpt(ctx context.Context) client.CallOption {
	if data, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && data != nil && data.Gate != nil {
		return client.WithBearer(data.Gate.BearerToken)
	}

	return client.WithBearer(nil)
}

// SessionOpt returns client.WithSession call option with token from context or with nil token.
func (n *layer) SessionOpt(ctx context.Context) client.CallOption {
	if data, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && data != nil && data.Gate != nil {
		return client.WithSession(data.Gate.SessionToken)
	}

	return client.WithSession(nil)
}

// Get NeoFS Object by refs.Address (should be used by auth.Center).
func (n *layer) Get(ctx context.Context, address *object.Address) (*object.Object, error) {
	ops := new(client.GetObjectParams).WithAddress(address)
	return n.pool.GetObject(ctx, ops, n.BearerOpt(ctx))
}

// GetBucketInfo returns bucket info by name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*cache.BucketInfo, error) {
	name, err := url.QueryUnescape(name)
	if err != nil {
		return nil, err
	}

	if bktInfo := n.bucketCache.Get(name); bktInfo != nil {
		return bktInfo, nil
	}

	containerID := new(cid.ID)
	if err := containerID.Parse(name); err != nil {
		list, err := n.containerList(ctx)
		if err != nil {
			return nil, err
		}
		for _, bkt := range list {
			if bkt.Name == name {
				return bkt, nil
			}
		}

		return nil, errors.GetAPIError(errors.ErrNoSuchBucket)
	}

	return n.containerInfo(ctx, containerID)
}

// GetBucketACL returns bucket acl info by name.
func (n *layer) GetBucketACL(ctx context.Context, name string) (*BucketACL, error) {
	inf, err := n.GetBucketInfo(ctx, name)
	if err != nil {
		return nil, err
	}

	eacl, err := n.GetContainerEACL(ctx, inf.CID)
	if err != nil {
		return nil, err
	}

	return &BucketACL{
		Info: inf,
		EACL: eacl,
	}, nil
}

// PutBucketACL put bucket acl by name.
func (n *layer) PutBucketACL(ctx context.Context, param *PutBucketACLParams) error {
	inf, err := n.GetBucketInfo(ctx, param.Name)
	if err != nil {
		return err
	}

	return n.setContainerEACLTable(ctx, inf.CID, param.EACL)
}

// ListBuckets returns all user containers. Name of the bucket is a container
// id. Timestamp is omitted since it is not saved in neofs container.
func (n *layer) ListBuckets(ctx context.Context) ([]*cache.BucketInfo, error) {
	return n.containerList(ctx)
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var err error

	params := &getParams{
		Writer: p.Writer,
		cid:    p.ObjectInfo.CID(),
		oid:    p.ObjectInfo.ID(),
		offset: p.Offset,
		length: p.Length,
	}

	if p.Range != nil {
		objRange := object.NewRange()
		objRange.SetOffset(p.Range.Start)
		// Range header is inclusive
		objRange.SetLength(p.Range.End - p.Range.Start + 1)
		params.Range = objRange
		_, err = n.objectRange(ctx, params)
	} else {
		_, err = n.objectGet(ctx, params)
	}

	if err != nil {
		n.objCache.Delete(p.ObjectInfo.Address())
		return fmt.Errorf("couldn't get object, cid: %s : %w", p.ObjectInfo.CID(), err)
	}

	return nil
}

// GetObjectInfo returns meta information about the object.
func (n *layer) GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*ObjectInfo, error) {
	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		n.log.Error("could not fetch bucket info", zap.Error(err))
		return nil, err
	}

	if len(p.VersionID) == 0 {
		return n.headLastVersionIfNotDeleted(ctx, bkt, p.Object)
	}

	return n.headVersion(ctx, bkt, p.VersionID)
}

func (n *layer) getSettingsObjectInfo(ctx context.Context, bkt *cache.BucketInfo) (*ObjectInfo, error) {
	if meta := n.systemCache.Get(bktVersionSettingsObject); meta != nil {
		return objInfoFromMeta(bkt, meta), nil
	}

	oid, err := n.objectFindID(ctx, &findParams{cid: bkt.CID, attr: objectSystemAttributeName, val: bktVersionSettingsObject})
	if err != nil {
		return nil, err
	}

	meta, err := n.objectHead(ctx, bkt.CID, oid)
	if err != nil {
		n.log.Error("could not fetch object head", zap.Error(err))
		return nil, err
	}
	if err = n.systemCache.Put(bktVersionSettingsObject, meta); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return objInfoFromMeta(bkt, meta), nil
}

// PutObject into storage.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*ObjectInfo, error) {
	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	return n.objectPut(ctx, bkt, p)
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error) {
	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObject,
			Writer:     pw,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	return n.PutObject(ctx, &PutObjectParams{
		Bucket: p.DstBucket,
		Object: p.DstObject,
		Size:   p.SrcSize,
		Reader: pr,
		Header: p.Header,
	})
}

// DeleteObject removes all objects with passed nice name.
func (n *layer) deleteObject(ctx context.Context, bkt *cache.BucketInfo, obj *VersionedObject) error {
	var (
		err error
		ids []*object.ID
	)

	versioningEnabled := n.isVersioningEnabled(ctx, bkt)
	if !versioningEnabled && obj.VersionID != unversionedObjectVersionID && obj.VersionID != "" {
		return errors.GetAPIError(errors.ErrInvalidVersion)
	}

	if versioningEnabled {
		p := &PutObjectParams{
			Object: obj.Name,
			Reader: bytes.NewReader(nil),
			Header: map[string]string{versionsDeleteMarkAttr: obj.VersionID},
		}
		if len(obj.VersionID) != 0 {
			id, err := n.checkVersionsExists(ctx, bkt, obj)
			if err != nil {
				return err
			}
			ids = []*object.ID{id}

			p.Header[versionsDelAttr] = obj.VersionID
		} else {
			p.Header[versionsDeleteMarkAttr] = delMarkFullObject
		}
		if _, err = n.objectPut(ctx, bkt, p); err != nil {
			return &errors.DeleteError{Err: err, Object: obj.String()}
		}
	} else {
		ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID, val: obj.Name})
		if err != nil {
			return &errors.DeleteError{Err: err, Object: obj.String()}
		}
	}

	for _, id := range ids {
		if err = n.objectDelete(ctx, bkt.CID, id); err != nil {
			return &errors.DeleteError{Err: err, Object: obj.String()}
		}
	}

	return nil
}

func (n *layer) checkVersionsExists(ctx context.Context, bkt *cache.BucketInfo, obj *VersionedObject) (*object.ID, error) {
	id := object.NewID()
	if err := id.Parse(obj.VersionID); err != nil {
		return nil, &errors.DeleteError{Err: errors.GetAPIError(errors.ErrInvalidVersion), Object: obj.String()}
	}

	versions, err := n.headVersions(ctx, bkt, obj.Name)
	if err != nil {
		return nil, &errors.DeleteError{Err: err, Object: obj.String()}
	}
	if !contains(getExistedVersions(versions), obj.VersionID) {
		return nil, &errors.DeleteError{Err: errors.GetAPIError(errors.ErrInvalidVersion), Object: obj.String()}
	}

	return id, nil
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, bucket string, objects []*VersionedObject) []error {
	var errs = make([]error, 0, len(objects))

	bkt, err := n.GetBucketInfo(ctx, bucket)
	if err != nil {
		return append(errs, err)
	}

	for i := range objects {
		if err := n.deleteObject(ctx, bkt, objects[i]); err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func (n *layer) CreateBucket(ctx context.Context, p *CreateBucketParams) (*cid.ID, error) {
	_, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchBucket) {
			return n.createContainer(ctx, p)
		}
		return nil, err
	}

	return nil, errors.GetAPIError(errors.ErrBucketAlreadyExists)
}

func (n *layer) DeleteBucket(ctx context.Context, p *DeleteBucketParams) error {
	bucketInfo, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		return err
	}

	ids, err := n.objectSearch(ctx, &findParams{cid: bucketInfo.CID})
	if err != nil {
		return err
	}
	if len(ids) != 0 {
		return errors.GetAPIError(errors.ErrBucketNotEmpty)
	}

	return n.deleteContainer(ctx, bucketInfo.CID)
}

func (n *layer) ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error) {
	var versions map[string]*objectVersions
	res := &ListObjectVersionsInfo{}

	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	cacheKey, err := createKey(ctx, bkt.CID, listVersionsMethod, p.Prefix, p.Delimiter)
	if err != nil {
		return nil, err
	}

	allObjects := n.listsCache.Get(cacheKey)
	if allObjects == nil {
		versions, err = n.getAllObjectsVersions(ctx, bkt, p.Prefix, p.Delimiter)
		if err != nil {
			return nil, err
		}

		sortedNames := make([]string, 0, len(versions))
		for k := range versions {
			sortedNames = append(sortedNames, k)
		}
		sort.Strings(sortedNames)

		allObjects = make([]*ObjectInfo, 0, p.MaxKeys)
		for _, name := range sortedNames {
			allObjects = append(allObjects, versions[name].getFiltered()...)
		}

		// putting to cache a copy of allObjects because allObjects can be modified further
		n.listsCache.Put(cacheKey, append([]*ObjectInfo(nil), allObjects...))
	}

	for i, obj := range allObjects {
		if obj.Name >= p.KeyMarker && obj.Version() >= p.VersionIDMarker {
			allObjects = allObjects[i:]
			break
		}
	}

	res.CommonPrefixes, allObjects = triageObjects(allObjects)

	if len(allObjects) > p.MaxKeys {
		res.IsTruncated = true
		res.NextKeyMarker = allObjects[p.MaxKeys].Name
		res.NextVersionIDMarker = allObjects[p.MaxKeys].Version()

		allObjects = allObjects[:p.MaxKeys]
		res.KeyMarker = allObjects[p.MaxKeys-1].Name
		res.VersionIDMarker = allObjects[p.MaxKeys-1].Version()
	}

	objects := make([]*ObjectVersionInfo, len(allObjects))
	for i, obj := range allObjects {
		objects[i] = &ObjectVersionInfo{Object: obj}
		if i == len(allObjects)-1 || allObjects[i+1].Name != obj.Name {
			objects[i].IsLatest = true
		}
	}

	res.Version, res.DeleteMarker = triageVersions(objects)
	return res, nil
}

func sortVersions(versions []*ObjectInfo) {
	sort.Slice(versions, func(i, j int) bool {
		return less(versions[i], versions[j])
	})
}

func triageVersions(objVersions []*ObjectVersionInfo) ([]*ObjectVersionInfo, []*ObjectVersionInfo) {
	if len(objVersions) == 0 {
		return nil, nil
	}

	var resVersion []*ObjectVersionInfo
	var resDelMarkVersions []*ObjectVersionInfo

	for _, version := range objVersions {
		if version.Object.Headers[versionsDeleteMarkAttr] == delMarkFullObject {
			resDelMarkVersions = append(resDelMarkVersions, version)
		} else {
			resVersion = append(resVersion, version)
		}
	}

	return resVersion, resDelMarkVersions
}

func less(ov1, ov2 *ObjectInfo) bool {
	if ov1.CreationEpoch == ov2.CreationEpoch {
		return ov1.Version() < ov2.Version()
	}
	return ov1.CreationEpoch < ov2.CreationEpoch
}

func contains(list []string, elem string) bool {
	for _, item := range list {
		if elem == item {
			return true
		}
	}
	return false
}

func (n *layer) PutBucketVersioning(ctx context.Context, p *PutVersioningParams) (*ObjectInfo, error) {
	bucketInfo, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	objectInfo, err := n.getSettingsObjectInfo(ctx, bucketInfo)
	if err != nil {
		n.log.Warn("couldn't get bucket version settings object, new one will be created",
			zap.String("bucket_name", bucketInfo.Name),
			zap.Stringer("cid", bucketInfo.CID),
			zap.Error(err))
	}

	attributes := make([]*object.Attribute, 0, 3)

	filename := object.NewAttribute()
	filename.SetKey(objectSystemAttributeName)
	filename.SetValue(bktVersionSettingsObject)

	createdAt := object.NewAttribute()
	createdAt.SetKey(object.AttributeTimestamp)
	createdAt.SetValue(strconv.FormatInt(time.Now().UTC().Unix(), 10))

	versioningIgnore := object.NewAttribute()
	versioningIgnore.SetKey(attrVersionsIgnore)
	versioningIgnore.SetValue(strconv.FormatBool(true))

	settingsVersioningEnabled := object.NewAttribute()
	settingsVersioningEnabled.SetKey(attrSettingsVersioningEnabled)
	settingsVersioningEnabled.SetValue(strconv.FormatBool(p.Settings.VersioningEnabled))

	attributes = append(attributes, filename, createdAt, versioningIgnore, settingsVersioningEnabled)

	raw := object.NewRaw()
	raw.SetOwnerID(bucketInfo.Owner)
	raw.SetContainerID(bucketInfo.CID)
	raw.SetAttributes(attributes...)

	ops := new(client.PutObjectParams).WithObject(raw.Object())
	oid, err := n.pool.PutObject(ctx, ops, n.BearerOpt(ctx))
	if err != nil {
		return nil, err
	}

	meta, err := n.objectHead(ctx, bucketInfo.CID, oid)
	if err != nil {
		return nil, err
	}

	if objectInfo != nil {
		if err = n.objectDelete(ctx, bucketInfo.CID, objectInfo.ID()); err != nil {
			return nil, err
		}
	}

	return objectInfoFromMeta(bucketInfo, meta, "", ""), nil
}

func (n *layer) GetBucketVersioning(ctx context.Context, bucketName string) (*BucketSettings, error) {
	bktInfo, err := n.GetBucketInfo(ctx, bucketName)
	if err != nil {
		return nil, err
	}

	return n.getBucketSettings(ctx, bktInfo)
}

func (n *layer) getBucketSettings(ctx context.Context, bktInfo *cache.BucketInfo) (*BucketSettings, error) {
	objInfo, err := n.getSettingsObjectInfo(ctx, bktInfo)
	if err != nil {
		return nil, err
	}

	return objectInfoToBucketSettings(objInfo), nil
}

func objectInfoToBucketSettings(info *ObjectInfo) *BucketSettings {
	res := &BucketSettings{}

	enabled, ok := info.Headers["S3-Settings-Versioning-enabled"]
	if ok {
		if parsed, err := strconv.ParseBool(enabled); err == nil {
			res.VersioningEnabled = parsed
		}
	}
	return res
}
