package layer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	stderrors "errors"
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
	"github.com/nspcc-dev/neofs-s3-gw/api/notifications"
	"github.com/nspcc-dev/neofs-s3-gw/api/resolver"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/token"
	"go.uber.org/zap"
)

// PrmContainerCreate groups parameters of NeoFS.CreateContainer operation.
type PrmContainerCreate struct {
	// NeoFS identifier of the container creator.
	Creator owner.ID

	// Container placement policy.
	Policy netmap.PlacementPolicy

	// Name for the container.
	Name string

	// Token of the container's creation session. Nil means session absence.
	SessionToken *session.Token

	// Time when container is created.
	Time time.Time

	// Basic ACL of the container.
	BasicACL acl.BasicACL

	// Attribute for LocationConstraint parameter (optional).
	LocationConstraintAttribute *container.Attribute
}

// PrmAuth groups authentication parameters for the NeoFS operation.
type PrmAuth struct {
	// Bearer token to be used for the operation. Overlaps PrivateKey. Optional.
	BearerToken *token.BearerToken

	// Private key used for the operation if BearerToken is missing (in this case non-nil).
	PrivateKey *ecdsa.PrivateKey
}

// PrmObjectSelect groups parameters of NeoFS.SelectObjects operation.
type PrmObjectSelect struct {
	// Authentication parameters.
	PrmAuth

	// Container to select the objects from.
	Container cid.ID

	// Key-value object attribute which should exactly be
	// presented in selected objects. Optional, empty key means any.
	ExactAttribute [2]string

	// File prefix of the selected objects. Optional, empty value means any.
	FilePrefix string
}

// PrmObjectRead groups parameters of NeoFS.ReadObject operation.
type PrmObjectRead struct {
	// Authentication parameters.
	PrmAuth

	// Container to read the object header from.
	Container cid.ID

	// ID of the object for which to read the header.
	Object oid.ID

	// Flag to read object header.
	WithHeader bool

	// Flag to read object payload. False overlaps payload range.
	WithPayload bool

	// Offset-length range of the object payload to be read.
	PayloadRange [2]uint64
}

// ObjectPart represents partially read NeoFS object.
type ObjectPart struct {
	// Object header with optional in-memory payload part.
	Head *object.Object

	// Object payload part encapsulated in io.Reader primitive.
	// Returns ErrAccessDenied on read access violation.
	Payload io.ReadCloser
}

// PrmObjectCreate groups parameters of NeoFS.CreateObject operation.
type PrmObjectCreate struct {
	// Authentication parameters.
	PrmAuth

	// Container to store the object.
	Container cid.ID

	// NeoFS identifier of the object creator.
	Creator owner.ID

	// Key-value object attributes.
	Attributes [][2]string

	// Full payload size (optional).
	PayloadSize uint64

	// Associated filename (optional).
	Filename string

	// Object payload encapsulated in io.Reader primitive.
	Payload io.Reader
}

// PrmObjectDelete groups parameters of NeoFS.DeleteObject operation.
type PrmObjectDelete struct {
	// Authentication parameters.
	PrmAuth

	// Container to delete the object from.
	Container cid.ID

	// Identifier of the removed object.
	Object oid.ID
}

// ErrAccessDenied is returned from NeoFS in case of access violation.
var ErrAccessDenied = stderrors.New("access denied")

// NeoFS represents virtual connection to NeoFS network.
type NeoFS interface {
	// CreateContainer creates and saves parameterized container in NeoFS.
	// Returns ID of the saved container.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the container to be created.
	CreateContainer(context.Context, PrmContainerCreate) (*cid.ID, error)

	// Container reads container from NeoFS by ID.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the container to be read.
	Container(context.Context, cid.ID) (*container.Container, error)

	// UserContainers reads list of the containers owned by specified user.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the containers to be listed.
	UserContainers(context.Context, owner.ID) ([]cid.ID, error)

	// SetContainerEACL saves eACL table of the container in NeoFS.
	//
	// Returns any error encountered which prevented the eACL to be saved.
	SetContainerEACL(context.Context, eacl.Table) error

	// ContainerEACL reads container eACL from NeoFS by container ID.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the eACL to be read.
	ContainerEACL(context.Context, cid.ID) (*eacl.Table, error)

	// DeleteContainer marks the container to be removed from NeoFS by ID.
	// Request is sent within session if the session token is specified.
	// Successful return does not guarantee the actual removal.
	//
	// Returns any error encountered which prevented the removal request to be sent.
	DeleteContainer(context.Context, cid.ID, *session.Token) error

	// SelectObjects perform object selection from the NeoFS container according
	// to specified parameters. Selects user objects only.
	//
	// Returns ErrAccessDenied on selection access violation.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the objects to be selected.
	SelectObjects(context.Context, PrmObjectSelect) ([]oid.ID, error)

	// ReadObject reads part of the object from the NeoFS container by identifier.
	// Exact part is returned according to the parameters:
	//   * with header only: empty payload (both in-mem and reader parts are nil);
	//   * with payload only: header is nil (zero range means full payload);
	//   * with header and payload: full in-mem object, payload reader is nil.
	//
	// WithHeader or WithPayload is true. Range length is positive if offset is positive.
	//
	// Payload reader should be closed if it is no longer needed.
	//
	// Returns ErrAccessDenied on read access violation.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the object header to be read.
	ReadObject(context.Context, PrmObjectRead) (*ObjectPart, error)

	// CreateObject creates and saves parameterized object in the NeoFS container.
	// Returns ID of the saved object.
	//
	// Creation time should be written into object (UTC).
	//
	// Returns ErrAccessDenied on write access violation.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the container to be created.
	CreateObject(context.Context, PrmObjectCreate) (*oid.ID, error)

	// DeleteObject marks the object to be removed from the NeoFS container by identifier.
	// Successful return does not guarantee the actual removal.
	//
	// Returns ErrAccessDenied on remove access violation.
	//
	// Returns any error encountered which prevented the removal request to be sent.
	DeleteObject(context.Context, PrmObjectDelete) error
}

type (
	layer struct {
		neoFS       NeoFS
		log         *zap.Logger
		anonKey     AnonymousKey
		resolver    *resolver.BucketResolver
		ncontroller *notifications.Controller
		listsCache  *cache.ObjectsListCache
		objCache    *cache.ObjectsCache
		namesCache  *cache.ObjectsNameCache
		bucketCache *cache.BucketCache
		systemCache *cache.SystemCache
	}

	Config struct {
		ChainAddress           string
		Caches                 *CachesConfig
		AnonKey                AnonymousKey
		Resolver               *resolver.BucketResolver
		NotificationController *notifications.Controller
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
		Range     *RangeParams
	}
	// CreateBucketParams stores bucket create request parameters.
	CreateBucketParams struct {
		Name               string
		ACL                uint32
		Policy             *netmap.PlacementPolicy
		EACL               *eacl.Table
		SessionToken       *session.Token
		LocationConstraint string
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

	// Client provides S3 API client interface.
	Client interface {
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
func NewLayer(log *zap.Logger, neoFS NeoFS, config *Config) Client {
	return &layer{
		neoFS:       neoFS,
		log:         log,
		anonKey:     config.AnonKey,
		resolver:    config.Resolver,
		listsCache:  cache.NewObjectsListCache(config.Caches.ObjectsList),
		ncontroller: config.NotificationController,
		objCache:    cache.New(config.Caches.Objects),
		namesCache:  cache.NewObjectsNameCache(config.Caches.Names),
		bucketCache: cache.NewBucketCache(config.Caches.Buckets),
		systemCache: cache.NewSystemCache(config.Caches.System),
	}
}

func (n *layer) EphemeralKey() *keys.PublicKey {
	return n.anonKey.Key.PublicKey()
}

func (n *layer) IsNotificationEnabled() bool {
	return n.ncontroller != nil
}

// IsAuthenticatedRequest check if access box exists in current request.
func IsAuthenticatedRequest(ctx context.Context) bool {
	_, ok := ctx.Value(api.BoxData).(*accessbox.Box)
	return ok
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (n *layer) Owner(ctx context.Context) *owner.ID {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		return bd.Gate.BearerToken.Issuer()
	}

	return owner.NewIDFromPublicKey((*ecdsa.PublicKey)(n.EphemeralKey()))
}

func (n *layer) prepareAuthParameters(ctx context.Context, prm *PrmAuth) {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		prm.BearerToken = bd.Gate.BearerToken
		return
	}

	prm.PrivateKey = &n.anonKey.Key.PrivateKey
}

// CallOptions returns []pool.CallOption options: client.WithBearer or client.WithKey (if request is anonymous).
func (n *layer) CallOptions(ctx context.Context) []pool.CallOption {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		return []pool.CallOption{pool.WithBearer(bd.Gate.BearerToken)}
	}

	return []pool.CallOption{pool.WithKey(&n.anonKey.Key.PrivateKey)}
}

// Get NeoFS Object by address (should be used by auth.Center).
func (n *layer) Get(ctx context.Context, addr *address.Address) (*object.Object, error) {
	return n.objectGet(ctx, addr)
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
func (n *layer) GetBucketACL(ctx context.Context, name string) (*BucketACL, error) {
	inf, err := n.GetBucketInfo(ctx, name)
	if err != nil {
		return nil, err
	}

	eACL, err := n.GetContainerEACL(ctx, inf.CID)
	if err != nil {
		return nil, err
	}

	return &BucketACL{
		Info: inf,
		EACL: eACL,
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
	var params getParams

	params.w = p.Writer
	params.oid = p.ObjectInfo.ID
	params.cid = p.ObjectInfo.CID

	if p.Range != nil {
		if p.Range.Start > p.Range.End {
			panic("invalid range")
		}

		params.off = p.Range.Start
		params.ln = p.Range.End - p.Range.Start + 1
	}

	err := n.objectWritePayload(ctx, params)
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

	return n.headVersion(ctx, bkt, p)
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
			Range:      p.Range,
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
		ids []*oid.ID
	)

	p := &PutObjectParams{
		Object: obj.Name,
		Reader: bytes.NewReader(nil),
		Header: map[string]string{},
	}

	versioningEnabled := n.isVersioningEnabled(ctx, bkt)

	// Current implementation doesn't consider "unversioned" mode (so any deletion creates "delete-mark" object).
	// The reason is difficulties to determinate whether versioning mode is "unversioned" or "suspended".

	if obj.VersionID == unversionedObjectVersionID || !versioningEnabled && len(obj.VersionID) == 0 {
		p.Header[versionsUnversionedAttr] = "true"
		versions, err := n.headVersions(ctx, bkt, obj.Name)
		if err != nil {
			obj.Error = err
			return obj
		}
		last := versions.getLast(FromUnversioned())
		if last == nil {
			obj.Error = errors.GetAPIError(errors.ErrInvalidVersion)
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
		ids = []*oid.ID{version.ID}
		if version.Headers[VersionsDeleteMarkAttr] == DelMarkFullObject {
			obj.DeleteMarkVersion = version.Version()
		}

		p.Header[versionsDelAttr] = obj.VersionID
		p.Header[VersionsDeleteMarkAttr] = version.Version()
	} else {
		p.Header[VersionsDeleteMarkAttr] = DelMarkFullObject
	}

	objInfo, err := n.objectPut(ctx, bkt, p)
	if err != nil {
		obj.Error = err
		return obj
	}
	if len(obj.VersionID) == 0 {
		obj.DeleteMarkVersion = objInfo.Version()
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
	bktInfo, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchBucket) {
			return n.createContainer(ctx, p)
		}
		return nil, err
	}

	if p.SessionToken != nil && bktInfo.Owner.Equal(p.SessionToken.OwnerID()) {
		return nil, errors.GetAPIError(errors.ErrBucketAlreadyOwnedByYou)
	}

	return nil, errors.GetAPIError(errors.ErrBucketAlreadyExists)
}

func (n *layer) ResolveBucket(ctx context.Context, name string) (*cid.ID, error) {
	cnrID := cid.New()
	if err := cnrID.Parse(name); err != nil {
		return n.resolver.Resolve(ctx, name)
	}

	return cnrID, nil
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
