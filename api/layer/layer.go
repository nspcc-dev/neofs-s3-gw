package layer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/url"
	"strconv"
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
		namesCache  cache.ObjectsNameCache
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
		Offset     int64
		Length     int64
		Writer     io.Writer
		VersionID  string
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

	// PutTaggingParams stores tag set params.
	PutTaggingParams struct {
		ObjectInfo *ObjectInfo
		TagSet     map[string]string
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
		PutObjectTagging(ctx context.Context, p *PutTaggingParams) error

		CopyObject(ctx context.Context, p *CopyObjectParams) (*ObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, bucket string, objects []*VersionedObject) []error
	}
)

const tagPrefix = "S3-Tag-"

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
		namesCache:  cache.NewObjectsNameCache(1000, time.Minute),
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
	if meta := n.systemCache.Get(bkt.SettingsObjectKey()); meta != nil {
		return objInfoFromMeta(bkt, meta), nil
	}

	oid, err := n.objectFindID(ctx, &findParams{cid: bkt.CID, attr: objectSystemAttributeName, val: bkt.SettingsObjectName()})
	if err != nil {
		return nil, err
	}

	meta, err := n.objectHead(ctx, bkt.CID, oid)
	if err != nil {
		n.log.Error("could not fetch object head", zap.Error(err))
		return nil, err
	}
	if err = n.systemCache.Put(bkt.SettingsObjectKey(), meta); err != nil {
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

// PutObjectTagging into storage.
func (n *layer) PutObjectTagging(ctx context.Context, p *PutTaggingParams) error {
	bktInfo := &cache.BucketInfo{
		Name:  p.ObjectInfo.Bucket,
		CID:   p.ObjectInfo.CID(),
		Owner: p.ObjectInfo.Owner,
	}

	if _, err := n.putSystemObject(ctx, bktInfo, p.ObjectInfo.TagsObject(), p.TagSet, tagPrefix); err != nil {
		return err
	}

	return nil
}

func (n *layer) putSystemObject(ctx context.Context, bktInfo *cache.BucketInfo, objName string, metadata map[string]string, prefix string) (*object.ID, error) {
	oldOID, err := n.objectFindID(ctx, &findParams{cid: bktInfo.CID, attr: objectSystemAttributeName, val: objName})
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}

	attributes := make([]*object.Attribute, 0, 3)

	filename := object.NewAttribute()
	filename.SetKey(objectSystemAttributeName)
	filename.SetValue(objName)

	createdAt := object.NewAttribute()
	createdAt.SetKey(object.AttributeTimestamp)
	createdAt.SetValue(strconv.FormatInt(time.Now().UTC().Unix(), 10))

	versioningIgnore := object.NewAttribute()
	versioningIgnore.SetKey(attrVersionsIgnore)
	versioningIgnore.SetValue(strconv.FormatBool(true))

	attributes = append(attributes, filename, createdAt, versioningIgnore)

	for k, v := range metadata {
		attr := object.NewAttribute()
		attr.SetKey(prefix + k)
		attr.SetValue(v)
		attributes = append(attributes, attr)
	}

	raw := object.NewRaw()
	raw.SetOwnerID(bktInfo.Owner)
	raw.SetContainerID(bktInfo.CID)
	raw.SetAttributes(attributes...)

	ops := new(client.PutObjectParams).WithObject(raw.Object())
	oid, err := n.pool.PutObject(ctx, ops, n.BearerOpt(ctx))
	if err != nil {
		return nil, err
	}

	if _, err = n.objectHead(ctx, bktInfo.CID, oid); err != nil {
		return nil, err
	}
	if oldOID != nil {
		if err = n.objectDelete(ctx, bktInfo.CID, oldOID); err != nil {
			return nil, err
		}
	}

	return oid, nil
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
			id, err := n.checkVersionsExist(ctx, bkt, obj)
			if err != nil {
				return err
			}
			ids = []*object.ID{id}

			p.Header[versionsDelAttr] = obj.VersionID
		} else {
			p.Header[versionsDeleteMarkAttr] = delMarkFullObject
		}
		if _, err = n.objectPut(ctx, bkt, p); err != nil {
			return err
		}
	} else {
		ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID, val: obj.Name})
		if err != nil {
			return err
		}
	}

	for _, id := range ids {
		if err = n.objectDelete(ctx, bkt.CID, id); err != nil {
			return err
		}
	}

	return nil
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, bucket string, objects []*VersionedObject) []error {
	var errs = make([]error, 0, len(objects))

	bkt, err := n.GetBucketInfo(ctx, bucket)
	if err != nil {
		return append(errs, err)
	}

	for _, obj := range objects {
		if err := n.deleteObject(ctx, bkt, obj); err != nil {
			errs = append(errs, &errors.ObjectError{Err: err, Object: obj.Name, Version: obj.VersionID})
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

	objects, err := n.listSortedObjectsFromNeoFS(ctx, allObjectParams{Bucket: bucketInfo})
	if err != nil {
		return err
	}
	if len(objects) != 0 {
		return errors.GetAPIError(errors.ErrBucketNotEmpty)
	}

	if err = n.deleteContainer(ctx, bucketInfo.CID); err != nil {
		return err
	}
	n.bucketCache.Delete(bucketInfo.Name)
	return nil
}
