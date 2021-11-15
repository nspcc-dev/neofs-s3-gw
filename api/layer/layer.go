package layer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

type (
	layer struct {
		pool        pool.Pool
		log         *zap.Logger
		anonKey     AnonymousKey
		listsCache  *cache.ObjectsListCache
		objCache    *cache.ObjectsCache
		namesCache  *cache.ObjectsNameCache
		bucketCache *cache.BucketCache
		systemCache *cache.SystemCache
	}

	// AnonymousKey contains data for anonymous requests.
	AnonymousKey struct {
		Key *keys.PrivateKey
	}

	// CachesConfig contains params for caches.
	CachesConfig struct {
		Objects     *cache.Config
		ObjectsList *cache.Config
		Names       *cache.Config
		Buckets     *cache.Config
		System      *cache.Config
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
		ObjectInfo *data.ObjectInfo
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

	// PutCORSParams stores PutCORS request parameters.
	PutCORSParams struct {
		BktInfo *data.BucketInfo
		Reader  io.Reader
	}

	// BucketSettings stores settings such as versioning.
	BucketSettings struct {
		VersioningEnabled bool
	}

	// CopyObjectParams stores object copy request parameters.
	CopyObjectParams struct {
		SrcObject *data.ObjectInfo
		DstBucket string
		DstObject string
		SrcSize   int64
		Header    map[string]string
	}
	// CreateBucketParams stores bucket create request parameters.
	CreateBucketParams struct {
		Name         string
		ACL          uint32
		Policy       *netmap.PlacementPolicy
		EACL         *eacl.Table
		SessionToken *session.Token
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

	// PutSystemObjectParams stores putSystemObject parameters.
	PutSystemObjectParams struct {
		BktInfo  *data.BucketInfo
		ObjName  string
		Metadata map[string]string
		Prefix   string
		Reader   io.Reader
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

	// VersionedObject stores info about objects to delete.
	VersionedObject struct {
		Name              string
		VersionID         string
		DeleteMarkVersion string
		Error             error
	}

	// PutTaggingParams stores tag set params.
	PutTaggingParams struct {
		ObjectInfo *data.ObjectInfo
		TagSet     map[string]string
	}

	// NeoFS provides basic NeoFS interface.
	NeoFS interface {
		Get(ctx context.Context, address *object.Address) (*object.Object, error)
	}

	// Client provides S3 API client interface.
	Client interface {
		NeoFS

		EphemeralKey() *keys.PublicKey

		PutBucketVersioning(ctx context.Context, p *PutVersioningParams) (*data.ObjectInfo, error)
		GetBucketVersioning(ctx context.Context, name string) (*BucketSettings, error)

		PutBucketCORS(ctx context.Context, p *PutCORSParams) error
		GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (*data.CORSConfiguration, error)
		DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error

		ListBuckets(ctx context.Context) ([]*data.BucketInfo, error)
		GetBucketInfo(ctx context.Context, name string) (*data.BucketInfo, error)
		GetBucketACL(ctx context.Context, name string) (*BucketACL, error)
		PutBucketACL(ctx context.Context, p *PutBucketACLParams) error
		CreateBucket(ctx context.Context, p *CreateBucketParams) (*cid.ID, error)
		DeleteBucket(ctx context.Context, p *DeleteBucketParams) error

		GetObject(ctx context.Context, p *GetObjectParams) error
		GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error)
		GetObjectTagging(ctx context.Context, p *data.ObjectInfo) (map[string]string, error)
		GetBucketTagging(ctx context.Context, bucket string) (map[string]string, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error)
		PutObjectTagging(ctx context.Context, p *PutTaggingParams) error
		PutBucketTagging(ctx context.Context, bucket string, tagSet map[string]string) error

		CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, bucket string, objects []*VersionedObject) ([]*VersionedObject, error)
		DeleteObjectTagging(ctx context.Context, p *data.ObjectInfo) error
		DeleteBucketTagging(ctx context.Context, bucket string) error
	}
)

const (
	tagPrefix    = "S3-Tag-"
	tagEmptyMark = "\\"
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

// DefaultCachesConfigs returns filled configs.
func DefaultCachesConfigs() *CachesConfig {
	return &CachesConfig{
		Objects:     cache.DefaultObjectsConfig(),
		ObjectsList: cache.DefaultObjectsListConfig(),
		Names:       cache.DefaultObjectsNameConfig(),
		Buckets:     cache.DefaultBucketConfig(),
		System:      cache.DefaultSystemConfig(),
	}
}

// NewLayer creates instance of layer. It checks credentials
// and establishes gRPC connection with node.
func NewLayer(log *zap.Logger, conns pool.Pool, config *CachesConfig, anonKey AnonymousKey) Client {
	return &layer{
		pool:        conns,
		log:         log,
		anonKey:     anonKey,
		listsCache:  cache.NewObjectsListCache(config.ObjectsList),
		objCache:    cache.New(config.Objects),
		namesCache:  cache.NewObjectsNameCache(config.Names),
		bucketCache: cache.NewBucketCache(config.Buckets),
		systemCache: cache.NewSystemCache(config.System),
	}
}

func (n *layer) EphemeralKey() *keys.PublicKey {
	return n.anonKey.Key.PublicKey()
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (n *layer) Owner(ctx context.Context) *owner.ID {
	if data, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && data != nil && data.Gate != nil {
		return data.Gate.BearerToken.Issuer()
	}

	id, _ := authmate.OwnerIDFromNeoFSKey(n.EphemeralKey())
	return id
}

// CallOptions returns []pool.CallOption options: client.WithBearer or client.WithKey (if request is anonymous).
func (n *layer) CallOptions(ctx context.Context) []pool.CallOption {
	if data, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && data != nil && data.Gate != nil {
		return []pool.CallOption{pool.WithBearer(data.Gate.BearerToken)}
	}

	return []pool.CallOption{pool.WithKey(&n.anonKey.Key.PrivateKey)}
}

// SessionOpt returns client.WithSession call option with token from context or with nil token.
func (n *layer) SessionOpt(ctx context.Context) pool.CallOption {
	if data, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && data != nil && data.Gate != nil {
		return pool.WithSession(data.Gate.SessionToken)
	}

	return pool.WithSession(nil)
}

// Get NeoFS Object by refs.Address (should be used by auth.Center).
func (n *layer) Get(ctx context.Context, address *object.Address) (*object.Object, error) {
	ops := new(client.GetObjectParams).WithAddress(address)
	return n.pool.GetObject(ctx, ops, n.CallOptions(ctx)...)
}

// GetBucketInfo returns bucket info by name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*data.BucketInfo, error) {
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
func (n *layer) ListBuckets(ctx context.Context) ([]*data.BucketInfo, error) {
	return n.containerList(ctx)
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var err error

	params := &getParams{
		Writer: p.Writer,
		cid:    p.ObjectInfo.CID,
		oid:    p.ObjectInfo.ID,
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
		_, err = n.objectGetWithPayloadWriter(ctx, params)
	}

	if err != nil {
		n.objCache.Delete(p.ObjectInfo.Address())
		return fmt.Errorf("couldn't get object, cid: %s : %w", p.ObjectInfo.CID, err)
	}

	return nil
}

// GetObjectInfo returns meta information about the object.
func (n *layer) GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error) {
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

// PutObject into storage.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error) {
	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	return n.objectPut(ctx, bkt, p)
}

// GetObjectTagging from storage.
func (n *layer) GetObjectTagging(ctx context.Context, oi *data.ObjectInfo) (map[string]string, error) {
	bktInfo := &data.BucketInfo{
		Name:  oi.Bucket,
		CID:   oi.CID,
		Owner: oi.Owner,
	}

	objInfo, err := n.headSystemObject(ctx, bktInfo, oi.TagsObject())
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}

	return formTagSet(objInfo), nil
}

// GetBucketTagging from storage.
func (n *layer) GetBucketTagging(ctx context.Context, bucketName string) (map[string]string, error) {
	bktInfo, err := n.GetBucketInfo(ctx, bucketName)
	if err != nil {
		return nil, err
	}

	objInfo, err := n.headSystemObject(ctx, bktInfo, formBucketTagObjectName(bucketName))

	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}

	return formTagSet(objInfo), nil
}

func formTagSet(objInfo *data.ObjectInfo) map[string]string {
	var tagSet map[string]string
	if objInfo != nil {
		tagSet = make(map[string]string, len(objInfo.Headers))
		for k, v := range objInfo.Headers {
			if strings.HasPrefix(k, tagPrefix) {
				if v == tagEmptyMark {
					v = ""
				}
				tagSet[strings.TrimPrefix(k, tagPrefix)] = v
			}
		}
	}
	return tagSet
}

// PutObjectTagging into storage.
func (n *layer) PutObjectTagging(ctx context.Context, p *PutTaggingParams) error {
	bktInfo := &data.BucketInfo{
		Name:  p.ObjectInfo.Bucket,
		CID:   p.ObjectInfo.CID,
		Owner: p.ObjectInfo.Owner,
	}

	s := &PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  p.ObjectInfo.TagsObject(),
		Metadata: p.TagSet,
		Prefix:   tagPrefix,
		Reader:   nil,
	}

	if _, err := n.putSystemObject(ctx, s); err != nil {
		return err
	}

	return nil
}

// PutBucketTagging into storage.
func (n *layer) PutBucketTagging(ctx context.Context, bucketName string, tagSet map[string]string) error {
	bktInfo, err := n.GetBucketInfo(ctx, bucketName)
	if err != nil {
		return err
	}

	s := &PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  formBucketTagObjectName(bucketName),
		Metadata: tagSet,
		Prefix:   tagPrefix,
		Reader:   nil,
	}

	if _, err = n.putSystemObject(ctx, s); err != nil {
		return err
	}

	return nil
}

// DeleteObjectTagging from storage.
func (n *layer) DeleteObjectTagging(ctx context.Context, p *data.ObjectInfo) error {
	bktInfo, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return err
	}
	return n.deleteSystemObject(ctx, bktInfo, p.TagsObject())
}

// DeleteBucketTagging from storage.
func (n *layer) DeleteBucketTagging(ctx context.Context, bucketName string) error {
	bktInfo, err := n.GetBucketInfo(ctx, bucketName)
	if err != nil {
		return err
	}

	return n.deleteSystemObject(ctx, bktInfo, formBucketTagObjectName(bucketName))
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error) {
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
func (n *layer) deleteObject(ctx context.Context, bkt *data.BucketInfo, obj *VersionedObject) *VersionedObject {
	var (
		err error
		ids []*object.ID
	)

	versioningEnabled := n.isVersioningEnabled(ctx, bkt)
	if !versioningEnabled && obj.VersionID != unversionedObjectVersionID && obj.VersionID != "" {
		obj.Error = errors.GetAPIError(errors.ErrInvalidVersion)
		return obj
	}

	if versioningEnabled {
		p := &PutObjectParams{
			Object: obj.Name,
			Reader: bytes.NewReader(nil),
			Header: map[string]string{versionsDeleteMarkAttr: obj.VersionID},
		}
		if len(obj.VersionID) != 0 {
			version, err := n.checkVersionsExist(ctx, bkt, obj)
			if err != nil {
				obj.Error = err
				return obj
			}
			ids = []*object.ID{version.ID}
			if version.Headers[versionsDeleteMarkAttr] == delMarkFullObject {
				obj.DeleteMarkVersion = version.Version()
			}

			p.Header[versionsDelAttr] = obj.VersionID
		} else {
			p.Header[versionsDeleteMarkAttr] = delMarkFullObject
		}
		objInfo, err := n.objectPut(ctx, bkt, p)
		if err != nil {
			obj.Error = err
			return obj
		}
		if len(obj.VersionID) == 0 {
			obj.DeleteMarkVersion = objInfo.Version()
		}
	} else {
		ids, err = n.objectSearch(ctx, &findParams{cid: bkt.CID, val: obj.Name})
		if err != nil {
			obj.Error = err
			return obj
		}
	}

	for _, id := range ids {
		if err = n.objectDelete(ctx, bkt.CID, id); err != nil {
			obj.Error = err
			return obj
		}
		if err = n.DeleteObjectTagging(ctx, &data.ObjectInfo{ID: id, Bucket: bkt.Name, Name: obj.Name}); err != nil {
			obj.Error = err
			return obj
		}
	}
	n.listsCache.CleanCacheEntriesContainingObject(obj.Name, bkt.CID)

	return obj
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, bucket string, objects []*VersionedObject) ([]*VersionedObject, error) {
	bkt, err := n.GetBucketInfo(ctx, bucket)
	if err != nil {
		return nil, err
	}

	for i, obj := range objects {
		objects[i] = n.deleteObject(ctx, bkt, obj)
	}

	return objects, nil
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

	objects, err := n.listSortedObjects(ctx, allObjectParams{Bucket: bucketInfo})
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
