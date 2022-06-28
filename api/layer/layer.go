package layer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
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
		neoFS       NeoFS
		log         *zap.Logger
		anonKey     AnonymousKey
		resolver    *resolver.BucketResolver
		ncontroller EventListener
		listsCache  *cache.ObjectsListCache
		objCache    *cache.ObjectsCache
		namesCache  *cache.ObjectsNameCache
		bucketCache *cache.BucketCache
		systemCache *cache.SystemCache
		treeService TreeService
	}

	Config struct {
		ChainAddress string
		Caches       *CachesConfig
		AnonKey      AnonymousKey
		Resolver     *resolver.BucketResolver
		TreeService  TreeService
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
		BucketInfo *data.BucketInfo
		Writer     io.Writer
	}

	// HeadObjectParams stores object head request parameters.
	HeadObjectParams struct {
		BktInfo   *data.BucketInfo
		Object    string
		VersionID string
	}

	// ObjectVersion stores object version info.
	ObjectVersion struct {
		BktInfo               *data.BucketInfo
		ObjectName            string
		VersionID             string
		NoErrorOnDeleteMarker bool
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
		BktInfo *data.BucketInfo
		Objects []*VersionedObject
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
		ScrBktInfo *data.BucketInfo
		DstBktInfo *data.BucketInfo
		DstObject  string
		SrcSize    int64
		Header     map[string]string
		Range      *RangeParams
		Lock       *data.ObjectLock
	}
	// CreateBucketParams stores bucket create request parameters.
	CreateBucketParams struct {
		Name                     string
		Policy                   netmap.PlacementPolicy
		EACL                     *eacl.Table
		SessionContainerCreation *session.Container
		SessionEACL              *session.Container
		LocationConstraint       string
		ObjectLockEnabled        bool
	}
	// PutBucketACLParams stores put bucket acl request parameters.
	PutBucketACLParams struct {
		BktInfo      *data.BucketInfo
		EACL         *eacl.Table
		SessionToken *session.Container
	}
	// DeleteBucketParams stores delete bucket request parameters.
	DeleteBucketParams struct {
		BktInfo      *data.BucketInfo
		SessionToken *session.Container
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
		GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ExtendedObjectInfo, error)

		GetLockInfo(ctx context.Context, obj *ObjectVersion) (*data.LockInfo, error)
		PutLockInfo(ctx context.Context, p *ObjectVersion, lock *data.ObjectLock) error

		GetBucketTagging(ctx context.Context, cnrID cid.ID) (map[string]string, error)
		PutBucketTagging(ctx context.Context, cnrID cid.ID, tagSet map[string]string) error
		DeleteBucketTagging(ctx context.Context, cnrID cid.ID) error

		GetObjectTagging(ctx context.Context, p *ObjectVersion) (string, map[string]string, error)
		PutObjectTagging(ctx context.Context, p *ObjectVersion, tagSet map[string]string) error
		DeleteObjectTagging(ctx context.Context, p *ObjectVersion) error

		PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, p *DeleteObjectParams) ([]*VersionedObject, error)

		CreateMultipartUpload(ctx context.Context, p *CreateMultipartParams) error
		CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*UploadData, *data.ObjectInfo, error)
		UploadPart(ctx context.Context, p *UploadPartParams) (string, error)
		UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error)
		ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error)
		AbortMultipartUpload(ctx context.Context, p *UploadInfoParams) error
		ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error)

		PutBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error
		GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error)

		// Compound methods for optimizations

		// GetObjectTaggingAndLock unifies GetObjectTagging and GetLock methods in single tree service invocation.
		GetObjectTaggingAndLock(ctx context.Context, p *ObjectVersion, nodeVersion *data.NodeVersion) (map[string]string, *data.LockInfo, error)
	}
)

const (
	tagPrefix = "S3-Tag-"
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

func (f MsgHandlerFunc) HandleMessage(ctx context.Context, msg *nats.Msg) error {
	return f(ctx, msg)
}

// DefaultCachesConfigs returns filled configs.
func DefaultCachesConfigs(logger *zap.Logger) *CachesConfig {
	return &CachesConfig{
		Objects:     cache.DefaultObjectsConfig(logger),
		ObjectsList: cache.DefaultObjectsListConfig(logger),
		Names:       cache.DefaultObjectsNameConfig(logger),
		Buckets:     cache.DefaultBucketConfig(logger),
		System:      cache.DefaultSystemConfig(logger),
	}
}

// NewLayer creates an instance of a layer. It checks credentials
// and establishes gRPC connection with the node.
func NewLayer(log *zap.Logger, neoFS NeoFS, config *Config) Client {
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
		treeService: config.TreeService,
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
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		return bearer.ResolveIssuer(*bd.Gate.BearerToken)
	}

	var ownerID user.ID
	user.IDFromKey(&ownerID, (ecdsa.PublicKey)(*n.EphemeralKey()))

	return ownerID
}

func (n *layer) prepareAuthParameters(ctx context.Context, prm *PrmAuth, bktOwner user.ID) {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		if bktOwner.Equals(bearer.ResolveIssuer(*bd.Gate.BearerToken)) {
			prm.BearerToken = bd.Gate.BearerToken
			return
		}
	}

	prm.PrivateKey = &n.anonKey.Key.PrivateKey
}

// GetBucketInfo returns bucket info by name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*data.BucketInfo, error) {
	name, err := url.QueryUnescape(name)
	if err != nil {
		return nil, fmt.Errorf("unescape bucket name: %w", err)
	}

	if bktInfo := n.bucketCache.Get(name); bktInfo != nil {
		return bktInfo, nil
	}

	containerID, err := n.ResolveBucket(ctx, name)
	if err != nil {
		n.log.Debug("bucket not found", zap.Error(err))
		return nil, errors.GetAPIError(errors.ErrNoSuchBucket)
	}

	return n.containerInfo(ctx, containerID)
}

// GetBucketACL returns bucket acl info by name.
func (n *layer) GetBucketACL(ctx context.Context, bktInfo *data.BucketInfo) (*BucketACL, error) {
	eACL, err := n.GetContainerEACL(ctx, bktInfo.CID)
	if err != nil {
		return nil, fmt.Errorf("get container eacl: %w", err)
	}

	return &BucketACL{
		Info: bktInfo,
		EACL: eACL,
	}, nil
}

// PutBucketACL puts bucket acl by name.
func (n *layer) PutBucketACL(ctx context.Context, param *PutBucketACLParams) error {
	return n.setContainerEACLTable(ctx, param.BktInfo.CID, param.EACL, param.SessionToken)
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
	params.bktInfo = p.BucketInfo

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
func (n *layer) GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ExtendedObjectInfo, error) {
	if len(p.VersionID) == 0 {
		return n.headLastVersionIfNotDeleted(ctx, p.BktInfo, p.Object)
	}

	return n.headVersion(ctx, p.BktInfo, p)
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error) {
	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObject,
			Writer:     pw,
			Range:      p.Range,
			BucketInfo: p.ScrBktInfo,
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

func getRandomOID() (oid.ID, error) {
	b := [32]byte{}
	if _, err := rand.Read(b[:]); err != nil {
		return oid.ID{}, err
	}

	var objID oid.ID
	objID.SetSHA256(b)
	return objID, nil
}

// DeleteObject removes all objects with the passed nice name.
func (n *layer) deleteObject(ctx context.Context, bkt *data.BucketInfo, obj *VersionedObject) *VersionedObject {
	if len(obj.VersionID) == 0 {
		obj.VersionID = UnversionedObjectVersionID
	}
	objVersion := &ObjectVersion{
		BktInfo:               bkt,
		ObjectName:            obj.Name,
		VersionID:             obj.VersionID,
		NoErrorOnDeleteMarker: true,
	}

	var nodeVersion *data.NodeVersion
	nodeVersion, obj.Error = n.getNodeVersion(ctx, objVersion)

	if obj.VersionID == UnversionedObjectVersionID {
		if obj.Error == nil {
			if obj.DeleteMarkVersion, obj.Error = n.removeOldVersion(ctx, bkt, nodeVersion, obj); obj.Error != nil {
				return obj
			}
		} else if !errors.IsS3Error(obj.Error, errors.ErrNoSuchKey) {
			return obj
		}

		randOID, err := getRandomOID()
		if err != nil {
			obj.Error = fmt.Errorf("couldn't get random oid: %w", err)
			return obj
		}

		newVersion := &data.NodeVersion{
			BaseNodeVersion: data.BaseNodeVersion{
				OID:      randOID,
				FilePath: obj.Name,
			},
			DeleteMarker: &data.DeleteMarkerInfo{
				Created: time.Now(),
				Owner:   n.Owner(ctx),
			},
			IsUnversioned: true,
		}

		if obj.Error = n.treeService.AddVersion(ctx, bkt.CID, newVersion); obj.Error != nil {
			return obj
		}

		n.namesCache.Delete(bkt.Name + "/" + obj.Name)
	} else {
		if obj.Error != nil {
			return obj
		}

		if obj.DeleteMarkVersion, obj.Error = n.removeOldVersion(ctx, bkt, nodeVersion, obj); obj.Error != nil {
			return obj
		}

		if obj.Error = n.treeService.RemoveVersion(ctx, bkt.CID, nodeVersion.ID); obj.Error != nil {
			return obj
		}
	}

	n.listsCache.CleanCacheEntriesContainingObject(obj.Name, bkt.CID)

	return obj
}

func (n *layer) removeOldVersion(ctx context.Context, bkt *data.BucketInfo, nodeVersion *data.NodeVersion, obj *VersionedObject) (string, error) {
	if nodeVersion.DeleteMarker != nil {
		return obj.VersionID, nil
	}

	return "", n.objectDelete(ctx, bkt, nodeVersion.OID)
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, p *DeleteObjectParams) ([]*VersionedObject, error) {
	for i, obj := range p.Objects {
		p.Objects[i] = n.deleteObject(ctx, p.BktInfo, obj)
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

	if p.SessionContainerCreation != nil && session.IssuedBy(*p.SessionContainerCreation, bktInfo.Owner) {
		return nil, errors.GetAPIError(errors.ErrBucketAlreadyOwnedByYou)
	}

	return nil, errors.GetAPIError(errors.ErrBucketAlreadyExists)
}

func (n *layer) ResolveBucket(ctx context.Context, name string) (cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(name); err != nil {
		return n.resolver.Resolve(ctx, name)
	}

	return cnrID, nil
}

func (n *layer) DeleteBucket(ctx context.Context, p *DeleteBucketParams) error {
	objects, _, err := n.getLatestObjectsVersions(ctx, allObjectParams{Bucket: p.BktInfo, MaxKeys: 1})
	if err != nil {
		return err
	}
	if len(objects) != 0 {
		return errors.GetAPIError(errors.ErrBucketNotEmpty)
	}

	n.bucketCache.Delete(p.BktInfo.Name)
	return n.neoFS.DeleteContainer(ctx, p.BktInfo.CID, p.SessionToken)
}
