package layer

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
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

	return n.containerInfo(ctx, containerID)
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

func getRandomOID() (*oid.ID, error) {
	b := [32]byte{}
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}

	var objID oid.ID
	objID.SetSHA256(b)
	return &objID, nil
}

// DeleteObject removes all objects with the passed nice name.
func (n *layer) deleteObject(ctx context.Context, bkt *data.BucketInfo, settings *data.BucketSettings, obj *VersionedObject) *VersionedObject {
	if len(obj.VersionID) == 0 || obj.VersionID == unversionedObjectVersionID {
		randOID, err := getRandomOID()
		if err != nil {
			obj.Error = fmt.Errorf("couldn't get random oid: %w", err)
			return obj
		}

		obj.DeleteMarkVersion = unversionedObjectVersionID
		newVersion := &NodeVersion{
			BaseNodeVersion: BaseNodeVersion{
				OID: *randOID,
			},
			IsDeleteMarker: true,
			IsUnversioned:  true,
		}

		if len(obj.VersionID) == 0 && settings.VersioningEnabled {
			newVersion.IsUnversioned = false
			obj.DeleteMarkVersion = randOID.String()
		}

		if obj.Error = n.treeService.AddVersion(ctx, bkt.CID, obj.Name, newVersion); obj.Error != nil {
			return obj
		}
	} else {
		versions, err := n.treeService.GetVersions(ctx, bkt.CID, obj.Name)
		if err != nil {
			obj.Error = err
			return obj
		}

		if obj.DeleteMarkVersion, obj.Error = n.removeVersionIfFound(ctx, bkt, versions, obj); obj.Error != nil {
			return obj
		}
	}

	n.listsCache.CleanCacheEntriesContainingObject(obj.Name, bkt.CID)

	return obj
}

func (n *layer) removeVersionIfFound(ctx context.Context, bkt *data.BucketInfo, versions []*NodeVersion, obj *VersionedObject) (string, error) {
	for _, version := range versions {
		if version.OID.String() != obj.VersionID {
			continue
		}

		var deleteMarkVersion string
		if version.IsDeleteMarker {
			deleteMarkVersion = obj.VersionID
		}

		if err := n.treeService.RemoveVersion(ctx, bkt.CID, version.ID); err != nil {
			return deleteMarkVersion, err
		}
		if err := n.objectDelete(ctx, bkt.CID, &version.OID); err != nil {
			return deleteMarkVersion, err
		}

		return deleteMarkVersion, n.DeleteObjectTagging(ctx, bkt, &data.ObjectInfo{ID: &version.OID, Bucket: bkt.Name, Name: obj.Name})
	}

	return "", errors.GetAPIError(errors.ErrNoSuchVersion)
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

	if p.SessionToken != nil && p.SessionToken.IssuedBy(*bktInfo.Owner) {
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
