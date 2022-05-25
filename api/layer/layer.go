package layer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

type (
	EventListener interface {
		Subscribe(context.Context, string, MsgHandler) error
		Listen(context.Context)
	}

	MsgHandler interface {
		HandleMessage(context.Context, *nats.Msg) error
	}

	MsgHandlerFunc func(context.Context, *nats.Msg) error

	layer struct {
		neoFS       neofs.NeoFS
		log         *zap.Logger
		anonKey     AnonymousKey
		resolver    *resolver.BucketResolver
		ncontroller EventListener
		listsCache  *cache.ObjectsListCache
		objCache    *cache.ObjectsCache
		namesCache  *cache.ObjectsNameCache
		bucketCache *cache.BucketCache
		systemCache *cache.SystemCache
	}

	Config struct {
		ChainAddress string
		Caches       *CachesConfig
		AnonKey      AnonymousKey
		Resolver     *resolver.BucketResolver
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

	// GetObjectParams stores object get request parameters.
	GetObjectParams struct {
		Range      *RangeParams
		ObjectInfo *data.ObjectInfo
		Writer     io.Writer
		VersionID  string
	}

	// HeadObjectParams stores object head request parameters.
	HeadObjectParams struct {
		BktInfo   *data.BucketInfo
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
		BktInfo *data.BucketInfo
		Object  string
		Size    int64
		Reader  io.Reader
		Header  map[string]string
		Lock    *data.ObjectLock
	}

	DeleteObjectParams struct {
		BktInfo     *data.BucketInfo
		BktSettings *data.BucketSettings
		Objects     []*VersionedObject
	}

	// PutSettingsParams stores object copy request parameters.
	PutSettingsParams struct {
		BktInfo  *data.BucketInfo
		Settings *data.BucketSettings
	}

	// PutCORSParams stores PutCORS request parameters.
	PutCORSParams struct {
		BktInfo *data.BucketInfo
		Reader  io.Reader
	}

	// CopyObjectParams stores object copy request parameters.
	CopyObjectParams struct {
		SrcObject  *data.ObjectInfo
		DstBktInfo *data.BucketInfo
		DstObject  string
		SrcSize    int64
		Header     map[string]string
		Range      *RangeParams
		Lock       *data.ObjectLock
	}
	// CreateBucketParams stores bucket create request parameters.
	CreateBucketParams struct {
		Name               string
		ACL                uint32
		Policy             *netmap.PlacementPolicy
		EACL               *eacl.Table
		SessionToken       *session.Container
		LocationConstraint string
		ObjectLockEnabled  bool
	}
	// PutBucketACLParams stores put bucket acl request parameters.
	PutBucketACLParams struct {
		BktInfo *data.BucketInfo
		EACL    *eacl.Table
	}
	// DeleteBucketParams stores delete bucket request parameters.
	DeleteBucketParams struct {
		BktInfo *data.BucketInfo
	}

	// PutSystemObjectParams stores putSystemObject parameters.
	PutSystemObjectParams struct {
		BktInfo  *data.BucketInfo
		ObjName  string
		Metadata map[string]string
		Prefix   string
		Reader   io.Reader
		Size     int64
		Lock     *data.ObjectLock
	}

	// ListObjectVersionsParams stores list objects versions parameters.
	ListObjectVersionsParams struct {
		BktInfo         *data.BucketInfo
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
		DeleteMarkerEtag  string
		Error             error
	}

	// PutTaggingParams stores tag set params.
	PutTaggingParams struct {
		ObjectInfo *data.ObjectInfo
		TagSet     map[string]string
	}

	// Client provides S3 API client interface.
	Client interface {
		Initialize(ctx context.Context, c EventListener) error
		EphemeralKey() *keys.PublicKey

		GetBucketSettings(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error)
		PutBucketSettings(ctx context.Context, p *PutSettingsParams) error

		PutBucketCORS(ctx context.Context, p *PutCORSParams) error
		GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (*data.CORSConfiguration, error)
		DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error

		ListBuckets(ctx context.Context) ([]*data.BucketInfo, error)
		GetBucketInfo(ctx context.Context, name string) (*data.BucketInfo, error)
		GetBucketACL(ctx context.Context, bktInfo *data.BucketInfo) (*BucketACL, error)
		PutBucketACL(ctx context.Context, p *PutBucketACLParams) error
		CreateBucket(ctx context.Context, p *CreateBucketParams) (*data.BucketInfo, error)
		DeleteBucket(ctx context.Context, p *DeleteBucketParams) error

		GetObject(ctx context.Context, p *GetObjectParams) error
		HeadSystemObject(ctx context.Context, bktInfo *data.BucketInfo, name string) (*data.ObjectInfo, error)
		GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error)
		GetObjectTagging(ctx context.Context, p *data.ObjectInfo) (map[string]string, error)
		GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error)
		PutSystemObject(ctx context.Context, p *PutSystemObjectParams) (*data.ObjectInfo, error)
		PutObjectTagging(ctx context.Context, p *PutTaggingParams) error
		PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string) error

		CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, p *DeleteObjectParams) ([]*VersionedObject, error)
		DeleteSystemObject(ctx context.Context, bktInfo *data.BucketInfo, name string) error
		DeleteObjectTagging(ctx context.Context, bktInfo *data.BucketInfo, objInfo *data.ObjectInfo) error
		DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error

		CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*data.ObjectInfo, error)
		UploadPart(ctx context.Context, p *UploadPartParams) (*data.ObjectInfo, error)
		UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error)
		ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error)
		AbortMultipartUpload(ctx context.Context, p *UploadInfoParams) error
		ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error)
		GetUploadInitInfo(ctx context.Context, p *UploadInfoParams) (*data.ObjectInfo, error)

		PutBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error
		GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error)
	}
)

const (
	tagPrefix    = "S3-Tag-"
	tagEmptyMark = "\\"
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

func (f MsgHandlerFunc) HandleMessage(ctx context.Context, msg *nats.Msg) error {
	return f(ctx, msg)
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

// NewLayer creates an instance of a layer. It checks credentials
// and establishes gRPC connection with the node.
func NewLayer(log *zap.Logger, neoFS neofs.NeoFS, config *Config) Client {
	return &layer{
		neoFS:       neoFS,
		log:         log,
		anonKey:     config.AnonKey,
		resolver:    config.Resolver,
		listsCache:  cache.NewObjectsListCache(config.Caches.ObjectsList),
		objCache:    cache.New(config.Caches.Objects),
		namesCache:  cache.NewObjectsNameCache(config.Caches.Names),
		bucketCache: cache.NewBucketCache(config.Caches.Buckets),
		systemCache: cache.NewSystemCache(config.Caches.System),
	}
}

func (n *layer) EphemeralKey() *keys.PublicKey {
	return n.anonKey.Key.PublicKey()
}

func (n *layer) Initialize(ctx context.Context, c EventListener) error {
	if n.IsNotificationEnabled() {
		return fmt.Errorf("already initialized")
	}

	// todo add notification handlers (e.g. for lifecycles)

	c.Listen(ctx)

	n.ncontroller = c
	return nil
}

func (n *layer) IsNotificationEnabled() bool {
	return n.ncontroller != nil
}

// IsAuthenticatedRequest checks if access box exists in the current request.
func IsAuthenticatedRequest(ctx context.Context) bool {
	_, ok := ctx.Value(api.BoxData).(*accessbox.Box)
	return ok
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (n *layer) Owner(ctx context.Context) user.ID {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		ownerID, _ := bd.Gate.BearerToken.Issuer()
		return ownerID
	}

	var ownerID user.ID
	user.IDFromKey(&ownerID, (ecdsa.PublicKey)(*n.EphemeralKey()))

	return ownerID
}

func (n *layer) prepareAuthParameters(ctx context.Context, prm *neofs.PrmAuth) {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		prm.BearerToken = bd.Gate.BearerToken
		return
	}

	prm.PrivateKey = &n.anonKey.Key.PrivateKey
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

	containerID, err := n.ResolveBucket(ctx, name)
	if err != nil {
		n.log.Debug("bucket not found", zap.Error(err))
		return nil, errors.GetAPIError(errors.ErrNoSuchBucket)
	}

	return n.containerInfo(ctx, *containerID)
}

// GetBucketACL returns bucket acl info by name.
func (n *layer) GetBucketACL(ctx context.Context, bktInfo *data.BucketInfo) (*BucketACL, error) {
	eACL, err := n.GetContainerEACL(ctx, bktInfo.CID)
	if err != nil {
		return nil, err
	}

	return &BucketACL{
		Info: bktInfo,
		EACL: eACL,
	}, nil
}

// PutBucketACL puts bucket acl by name.
func (n *layer) PutBucketACL(ctx context.Context, param *PutBucketACLParams) error {
	return n.setContainerEACLTable(ctx, param.BktInfo.CID, param.EACL)
}

// ListBuckets returns all user containers. The name of the bucket is a container
// id. Timestamp is omitted since it is not saved in neofs container.
func (n *layer) ListBuckets(ctx context.Context) ([]*data.BucketInfo, error) {
	return n.containerList(ctx)
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var params getParams

	params.oid = p.ObjectInfo.ID
	params.cid = p.ObjectInfo.CID

	if p.Range != nil {
		if p.Range.Start > p.Range.End {
			panic("invalid range")
		}

		params.off = p.Range.Start
		params.ln = p.Range.End - p.Range.Start + 1
	}

	payload, err := n.initObjectPayloadReader(ctx, params)
	if err != nil {
		return fmt.Errorf("init object payload reader: %w", err)
	}

	if params.ln == 0 {
		params.ln = 4096 // configure?
	}

	// alloc buffer for copying
	buf := make([]byte, params.ln) // sync-pool it?

	// copy full payload
	_, err = io.CopyBuffer(p.Writer, payload, buf)
	if err != nil {
		return fmt.Errorf("copy object payload: %w", err)
	}

	return nil
}

// GetObjectInfo returns meta information about the object.
func (n *layer) GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error) {
	if len(p.VersionID) == 0 {
		return n.headLastVersionIfNotDeleted(ctx, p.BktInfo, p.Object)
	}

	return n.headVersion(ctx, p.BktInfo, p)
}

// GetObjectTagging from storage.
func (n *layer) GetObjectTagging(ctx context.Context, oi *data.ObjectInfo) (map[string]string, error) {
	bktInfo := &data.BucketInfo{
		Name:  oi.Bucket,
		CID:   oi.CID,
		Owner: oi.Owner,
	}

	objInfo, err := n.HeadSystemObject(ctx, bktInfo, oi.TagsObject())
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}

	return formTagSet(objInfo), nil
}

// GetBucketTagging from storage.
func (n *layer) GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error) {
	objInfo, err := n.HeadSystemObject(ctx, bktInfo, formBucketTagObjectName(bktInfo.Name))
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

	_, err := n.PutSystemObject(ctx, s)
	return err
}

// PutBucketTagging into storage.
func (n *layer) PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string) error {
	s := &PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  formBucketTagObjectName(bktInfo.Name),
		Metadata: tagSet,
		Prefix:   tagPrefix,
		Reader:   nil,
	}

	_, err := n.PutSystemObject(ctx, s)
	return err
}

// DeleteObjectTagging from storage.
func (n *layer) DeleteObjectTagging(ctx context.Context, bktInfo *data.BucketInfo, objInfo *data.ObjectInfo) error {
	return n.DeleteSystemObject(ctx, bktInfo, objInfo.TagsObject())
}

// DeleteBucketTagging from storage.
func (n *layer) DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error {
	return n.DeleteSystemObject(ctx, bktInfo, formBucketTagObjectName(bktInfo.Name))
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error) {
	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObject,
			Writer:     pw,
			Range:      p.Range,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	return n.PutObject(ctx, &PutObjectParams{
		BktInfo: p.DstBktInfo,
		Object:  p.DstObject,
		Size:    p.SrcSize,
		Reader:  pr,
		Header:  p.Header,
	})
}

// DeleteObject removes all objects with the passed nice name.
func (n *layer) deleteObject(ctx context.Context, bkt *data.BucketInfo, settings *data.BucketSettings, obj *VersionedObject) *VersionedObject {
	var (
		err error
		ids []oid.ID
	)

	p := &PutObjectParams{
		BktInfo: bkt,
		Object:  obj.Name,
		Reader:  bytes.NewReader(nil),
		Header:  map[string]string{},
	}

	// Current implementation doesn't consider "unversioned" mode (so any deletion creates "delete-mark" object).
	// The reason is difficulties to determinate whether versioning mode is "unversioned" or "suspended".

	if obj.VersionID == unversionedObjectVersionID || !settings.VersioningEnabled && len(obj.VersionID) == 0 {
		p.Header[versionsUnversionedAttr] = "true"
		versions, err := n.headVersions(ctx, bkt, obj.Name)
		if err != nil {
			obj.Error = err
			return obj
		}
		last := versions.getLast(FromUnversioned())
		if last == nil {
			return obj
		}
		p.Header[VersionsDeleteMarkAttr] = last.Version()

		for _, unversioned := range versions.unversioned() {
			ids = append(ids, unversioned.ID)
		}
	} else if len(obj.VersionID) != 0 {
		version, err := n.checkVersionsExist(ctx, bkt, obj)
		if err != nil {
			obj.Error = err
			return obj
		}
		ids = []oid.ID{version.ID}
		if version.Headers[VersionsDeleteMarkAttr] == DelMarkFullObject {
			obj.DeleteMarkVersion = version.Version()
		}

		p.Header[versionsDelAttr] = obj.VersionID
		p.Header[VersionsDeleteMarkAttr] = version.Version()
	} else {
		p.Header[VersionsDeleteMarkAttr] = DelMarkFullObject
	}

	for _, id := range ids {
		if err = n.objectDelete(ctx, bkt.CID, id); err != nil {
			obj.Error = err
			return obj
		}
		if err = n.DeleteObjectTagging(ctx, bkt, &data.ObjectInfo{ID: id, Bucket: bkt.Name, Name: obj.Name}); err != nil {
			obj.Error = err
			return obj
		}
	}
	n.listsCache.CleanCacheEntriesContainingObject(obj.Name, bkt.CID)

	objInfo, err := n.PutObject(ctx, p)
	if err != nil {
		obj.Error = err
		return obj
	}
	if len(obj.VersionID) == 0 {
		obj.DeleteMarkVersion = objInfo.Version()
		if settings.VersioningEnabled {
			obj.DeleteMarkerEtag = objInfo.HashSum
		}
	}

	return obj
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, p *DeleteObjectParams) ([]*VersionedObject, error) {
	for i, obj := range p.Objects {
		p.Objects[i] = n.deleteObject(ctx, p.BktInfo, p.BktSettings, obj)
	}

	return p.Objects, nil
}

func (n *layer) CreateBucket(ctx context.Context, p *CreateBucketParams) (*data.BucketInfo, error) {
	bktInfo, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchBucket) {
			return n.createContainer(ctx, p)
		}
		return nil, err
	}

	if p.SessionToken != nil && session.IssuedBy(*p.SessionToken, bktInfo.Owner) {
		return nil, errors.GetAPIError(errors.ErrBucketAlreadyOwnedByYou)
	}

	return nil, errors.GetAPIError(errors.ErrBucketAlreadyExists)
}

func (n *layer) ResolveBucket(ctx context.Context, name string) (*cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(name); err != nil {
		return n.resolver.Resolve(ctx, name)
	}

	return &cnrID, nil
}

func (n *layer) DeleteBucket(ctx context.Context, p *DeleteBucketParams) error {
	objects, err := n.listSortedObjects(ctx, allObjectParams{Bucket: p.BktInfo})
	if err != nil {
		return err
	}
	if len(objects) != 0 {
		return errors.GetAPIError(errors.ErrBucketNotEmpty)
	}

	n.bucketCache.Delete(p.BktInfo.Name)
	return n.deleteContainer(ctx, p.BktInfo.CID)
}
