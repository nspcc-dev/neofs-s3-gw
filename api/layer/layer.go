package layer

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
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
		neoFS NeoFS
		log   *zap.Logger
		// used in case of user wants to do something like anonymous.
		// Typical using is a flag --no-sign-request in aws-cli.
		anonymous   user.ID
		resolver    Resolver
		ncontroller EventListener
		cache       *Cache
		buffers     *sync.Pool
	}

	Config struct {
		ChainAddress string
		Caches       *CachesConfig
		GateKey      *keys.PrivateKey
		Anonymous    user.ID
		Resolver     Resolver
	}

	// GetObjectParams stores object get request parameters.
	GetObjectParams struct {
		Range      *RangeParams
		ObjectInfo *data.ObjectInfo
		BucketInfo *data.BucketInfo
		Writer     io.Writer
		Encryption encryption.Params
	}

	// HeadObjectParams stores object head request parameters.
	HeadObjectParams struct {
		BktInfo                   *data.BucketInfo
		Object                    string
		VersionID                 string
		IsBucketVersioningEnabled bool
	}

	// ShortInfoParams stores necessary info to get actual obj info in versioned container for non versioned request.
	ShortInfoParams struct {
		CID             cid.ID
		Owner           user.ID
		Object          string
		FindNullVersion bool
	}

	// ObjectVersion stores object version info.
	ObjectVersion struct {
		BktInfo    *data.BucketInfo
		ObjectName string
		VersionID  string
	}

	// Resolver allows to map container ID by container name.
	Resolver interface {
		ResolveCID(ctx context.Context, containerName string) (cid.ID, error)
	}

	// RangeParams stores range header request parameters.
	RangeParams struct {
		Start uint64
		End   uint64
	}

	// PutObjectParams stores object put request parameters.
	PutObjectParams struct {
		BktInfo      *data.BucketInfo
		Object       string
		Size         int64
		Reader       io.Reader
		Header       map[string]string
		Lock         *data.ObjectLock
		Encryption   encryption.Params
		CopiesNumber uint32
	}

	DeleteObjectParams struct {
		BktInfo  *data.BucketInfo
		Objects  []*VersionedObject
		Settings *data.BucketSettings
	}

	// PutSettingsParams stores object copy request parameters.
	PutSettingsParams struct {
		BktInfo      *data.BucketInfo
		Settings     *data.BucketSettings
		CopiesNumber uint32
	}

	// PutCORSParams stores PutCORS request parameters.
	PutCORSParams struct {
		BktInfo      *data.BucketInfo
		Reader       io.Reader
		CopiesNumber uint32
	}

	// CopyObjectParams stores object copy request parameters.
	CopyObjectParams struct {
		SrcObject   *data.ObjectInfo
		ScrBktInfo  *data.BucketInfo
		DstBktInfo  *data.BucketInfo
		DstObject   string
		SrcSize     int64
		Header      map[string]string
		Range       *RangeParams
		Lock        *data.ObjectLock
		Encryption  encryption.Params
		CopiesNuber uint32
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

	// GetObjectWithPayloadReaderParams describes params for Client.GetObjectWithPayloadReader.
	GetObjectWithPayloadReaderParams struct {
		Owner   user.ID
		BktInfo *data.BucketInfo
		Object  oid.ID
	}

	// ObjectWithPayloadReader is a response for Client.GetObjectWithPayloadReader.
	ObjectWithPayloadReader struct {
		Head       *object.Object
		Payload    io.ReadCloser
		ObjectInfo *data.ObjectInfo
	}

	// Client provides S3 API client interface.
	Client interface {
		Initialize(ctx context.Context, c EventListener) error

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
		GetObjectWithPayloadReader(ctx context.Context, p *GetObjectWithPayloadReaderParams) (*ObjectWithPayloadReader, error)
		GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error)
		GetExtendedObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ExtendedObjectInfo, error)
		ComprehensiveObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ComprehensiveObjectInfo, error)
		GetIDForVersioningContainer(ctx context.Context, p *ShortInfoParams) (oid.ID, error)

		GetLockInfo(ctx context.Context, obj *ObjectVersion) (*data.LockInfo, error)
		PutLockInfo(ctx context.Context, p *PutLockInfoParams) error

		GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error)
		PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string, copiesNumber uint32) error
		DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error

		GetObjectTagging(ctx context.Context, p *GetObjectTaggingParams) (string, map[string]string, error)
		PutObjectTagging(ctx context.Context, p *PutObjectTaggingParams) error
		DeleteObjectTagging(ctx context.Context, p *ObjectVersion) error

		PutObject(ctx context.Context, p *PutObjectParams) (*data.ExtendedObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ExtendedObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, p *DeleteObjectParams) []*VersionedObject

		CreateMultipartUpload(ctx context.Context, p *CreateMultipartParams) (string, error)
		CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*UploadData, *data.ExtendedObjectInfo, error)
		UploadPart(ctx context.Context, p *UploadPartParams) (string, error)
		UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error)
		ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error)
		AbortMultipartUpload(ctx context.Context, p *UploadInfoParams) error
		ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error)

		PutBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error
		GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error)

		// Compound methods for optimizations

		// GetObjectTaggingAndLock unifies GetObjectTagging and GetLock methods in single tree service invocation.
		GetObjectTaggingAndLock(ctx context.Context, p *ObjectVersion) (map[string]string, *data.LockInfo, error)
	}
)

const (
	tagPrefix = "S3-Tag-"

	AESEncryptionAlgorithm       = "AES256"
	AESKeySize                   = 32
	AttributeEncryptionAlgorithm = api.NeoFSSystemMetadataPrefix + "Algorithm"
	AttributeDecryptedSize       = api.NeoFSSystemMetadataPrefix + "Decrypted-Size"
	AttributeHMACSalt            = api.NeoFSSystemMetadataPrefix + "HMAC-Salt"
	AttributeHMACKey             = api.NeoFSSystemMetadataPrefix + "HMAC-Key"

	AttributeNeofsCopiesNumber = "neofs-copies-number" // such format to match X-Amz-Meta-Neofs-Copies-Number header
)

var (
	errPubKeyNotExists = errors.New("pub key not exists")
)

var (
	// ErrNodeNotFound is returned from Tree service in case of not found error.
	ErrNodeNotFound = errors.New("not found")

	// ErrNodeAccessDenied is returned from Tree service in case of access denied error.
	ErrNodeAccessDenied = errors.New("access denied")

	// ErrPartListIsEmpty is returned if no parts available for the upload.
	ErrPartListIsEmpty = errors.New("part list is empty")
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

func (f MsgHandlerFunc) HandleMessage(ctx context.Context, msg *nats.Msg) error {
	return f(ctx, msg)
}

// NewLayer creates an instance of a layer. It checks credentials
// and establishes gRPC connection with the node.
func NewLayer(log *zap.Logger, neoFS NeoFS, config *Config) Client {
	buffers := sync.Pool{}
	buffers.New = func() any {
		b := make([]byte, neoFS.MaxObjectSize())
		return &b
	}

	return &layer{
		neoFS:     neoFS,
		log:       log,
		anonymous: config.Anonymous,
		resolver:  config.Resolver,
		cache:     NewCache(config.Caches),
		buffers:   &buffers,
	}
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

// TimeNow returns client time from request or time.Now().
func TimeNow(ctx context.Context) time.Time {
	if now, ok := ctx.Value(api.ClientTime).(time.Time); ok {
		return now
	}

	return time.Now()
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (n *layer) Owner(ctx context.Context) user.ID {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		return bd.Gate.BearerToken.ResolveIssuer()
	}

	return n.anonymous
}

// OwnerPublicKey returns owner public key from BearerToken (context).
func (n *layer) OwnerPublicKey(ctx context.Context) (*keys.PublicKey, error) {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		if sig, ok := bd.Gate.BearerToken.Signature(); ok {
			var pk keys.PublicKey
			if err := pk.DecodeBytes(sig.PublicKeyBytes()); err != nil {
				return nil, fmt.Errorf("pub key decode: %w", err)
			}

			return &pk, nil
		}
	}

	return nil, errPubKeyNotExists
}

func (n *layer) prepareAuthParameters(ctx context.Context, prm *PrmAuth, bktOwner user.ID) {
	prm.BearerToken = bearerTokenFromContext(ctx, bktOwner)
}

func bearerTokenFromContext(ctx context.Context, bktOwner user.ID) *bearer.Token {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		if bktOwner == bd.Gate.BearerToken.ResolveIssuer() {
			return bd.Gate.BearerToken
		}
	}
	return nil
}

// GetBucketInfo returns bucket info by name.
func (n *layer) GetBucketInfo(ctx context.Context, name string) (*data.BucketInfo, error) {
	name, err := url.QueryUnescape(name)
	if err != nil {
		return nil, fmt.Errorf("unescape bucket name: %w", err)
	}

	if bktInfo := n.cache.GetBucket(name); bktInfo != nil {
		return bktInfo, nil
	}

	containerID, err := n.ResolveBucket(ctx, name)
	if err != nil {
		n.log.Debug("bucket not found", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchBucket)
	}

	return n.containerInfo(ctx, containerID)
}

// GetBucketACL returns bucket acl info by name.
func (n *layer) GetBucketACL(ctx context.Context, bktInfo *data.BucketInfo) (*BucketACL, error) {
	var eACL = n.cache.GetBucketACL(bktInfo.CID)

	if eACL != nil {
		return &BucketACL{Info: bktInfo, EACL: eACL}, nil
	}
	eACL, err := n.GetContainerEACL(ctx, bktInfo.CID)
	if err != nil {
		return nil, fmt.Errorf("get container eacl: %w", err)
	}
	n.cache.PutBucketACL(bktInfo.CID, eACL)

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

// GetObjectWithPayloadReader returns object head and payload Reader.
func (n *layer) GetObjectWithPayloadReader(ctx context.Context, p *GetObjectWithPayloadReaderParams) (*ObjectWithPayloadReader, error) {
	var prm = GetObject{
		Container: p.BktInfo.CID,
		Object:    p.Object,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, p.Owner)

	op, err := n.neoFS.GetObject(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}

	return &ObjectWithPayloadReader{
		Head:       op.Head,
		Payload:    op.Payload,
		ObjectInfo: objectInfoFromMeta(p.BktInfo, op.Head),
	}, nil
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var params getParams

	params.oid = p.ObjectInfo.ID
	params.bktInfo = p.BucketInfo

	var decReader *encryption.Decrypter
	if p.Encryption.Enabled() {
		var err error
		decReader, err = getDecrypter(p)
		if err != nil {
			return fmt.Errorf("creating decrypter: %w", err)
		}
		params.off = decReader.EncryptedOffset()
		params.ln = decReader.EncryptedLength()
	} else {
		if p.Range != nil {
			if p.Range.Start > p.Range.End {
				panic("invalid range")
			}
			params.ln = p.Range.End - p.Range.Start + 1
			params.off = p.Range.Start
		}
	}

	payload, err := n.initObjectPayloadReader(ctx, params)
	if err != nil {
		return fmt.Errorf("init object payload reader: %w", err)
	}

	bufSize := uint64(32 * 1024) // configure?
	if params.ln != 0 && params.ln < bufSize {
		bufSize = params.ln
	}

	// alloc buffer for copying
	buf := make([]byte, bufSize) // sync-pool it?

	r := payload
	if decReader != nil {
		if err = decReader.SetReader(payload); err != nil {
			return fmt.Errorf("set reader to decrypter: %w", err)
		}
		r = io.LimitReader(decReader, int64(decReader.DecryptedLength()))
	}

	// copy full payload
	written, err := io.CopyBuffer(p.Writer, r, buf)
	if err != nil {
		if decReader != nil {
			return fmt.Errorf("copy object payload written: '%d', decLength: '%d', params.ln: '%d' : %w", written, decReader.DecryptedLength(), params.ln, err)
		}
		return fmt.Errorf("copy object payload written: '%d': %w", written, err)
	}

	return nil
}

func getDecrypter(p *GetObjectParams) (*encryption.Decrypter, error) {
	var encRange *encryption.Range
	if p.Range != nil {
		encRange = &encryption.Range{Start: p.Range.Start, End: p.Range.End}
	}

	header := p.ObjectInfo.Headers[UploadCompletedParts]
	if len(header) == 0 {
		return encryption.NewDecrypter(p.Encryption, uint64(p.ObjectInfo.Size), encRange)
	}

	decryptedObjectSize, err := strconv.ParseUint(p.ObjectInfo.Headers[AttributeDecryptedSize], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse decrypted size: %w", err)
	}

	splits := strings.Split(header, ",")
	sizes := make([]uint64, len(splits))
	for i, splitInfo := range splits {
		part, err := ParseCompletedPartHeader(splitInfo)
		if err != nil {
			return nil, fmt.Errorf("parse completed part: %w", err)
		}
		sizes[i] = uint64(part.Size)
	}

	return encryption.NewMultipartDecrypter(p.Encryption, decryptedObjectSize, sizes, encRange)
}

// GetObjectInfo returns meta information about the object.
func (n *layer) GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error) {
	extendedObjectInfo, err := n.GetExtendedObjectInfo(ctx, p)
	if err != nil {
		return nil, err
	}

	return extendedObjectInfo.ObjectInfo, nil
}

// GetExtendedObjectInfo returns meta information and corresponding info from the tree service about the object.
func (n *layer) GetExtendedObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ExtendedObjectInfo, error) {
	var (
		id       oid.ID
		err      error
		settings *data.BucketSettings
		owner    = n.Owner(ctx)
	)

	if len(p.VersionID) == 0 {
		heads, err := n.searchAllVersionsInNeoFS(ctx, p.BktInfo, owner, p.Object, false)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
			}

			return nil, err
		}

		if heads[0].IsDeleteMarker {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}

		id = heads[0].ID
	} else if p.VersionID == data.UnversionedObjectVersionID {
		versions, err := n.searchAllVersionsInNeoFS(ctx, p.BktInfo, owner, p.Object, true)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
			}

			return nil, err
		}

		id = versions[0].ID
	} else {
		settings, err = n.GetBucketSettings(ctx, p.BktInfo)
		if err != nil {
			return nil, fmt.Errorf("get bucket settings: %w", err)
		}

		versions, err := n.searchAllVersionsInNeoFS(ctx, p.BktInfo, owner, p.Object, false)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
			}
			return nil, err
		}

		var foundVersion *allVersionsSearchResult

		if settings.VersioningEnabled() {
			for _, version := range versions {
				if version.ID.EncodeToString() == p.VersionID {
					foundVersion = &version
					break
				}
			}
		} else {
			// If versioning is not enabled, user "should see" only last version of uploaded object.
			if versions[0].ID.EncodeToString() == p.VersionID {
				foundVersion = &versions[0]
			}
		}

		if foundVersion == nil {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
		}

		id = foundVersion.ID
	}

	meta, err := n.objectHead(ctx, p.BktInfo, id) // latest version.
	if err != nil {
		return nil, fmt.Errorf("get head failed: %w", err)
	}

	objInfo := objectInfoFromMeta(p.BktInfo, meta)

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: &data.NodeVersion{},
	}

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("get object",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", p.BktInfo.Name),
		zap.Stringer("cid", p.BktInfo.CID),
		zap.String("object", objInfo.Name),
		zap.Stringer("oid", objInfo.ID))

	return extObjInfo, nil
}

func (n *layer) ComprehensiveObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ComprehensiveObjectInfo, error) {
	var (
		id                oid.ID
		err               error
		owner             = n.Owner(ctx)
		versions          []allVersionsSearchResult
		hasTags, hasLocks bool

		tagSet         map[string]string
		lockInfo       *data.LockInfo
		isEmptyVersion = len(p.VersionID) == 0
		isNullVersion  = p.VersionID == data.UnversionedObjectVersionID
	)

	if isEmptyVersion || isNullVersion {
		versions, hasTags, hasLocks, err = n.comprehensiveSearchAllVersionsInNeoFS(ctx, p.BktInfo, owner, p.Object, isNullVersion)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				if isEmptyVersion {
					return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
				}

				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
			}

			return nil, err
		}

		if isEmptyVersion {
			if versions[0].IsDeleteMarker {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
			}
		}

		id = versions[0].ID

		if p.IsBucketVersioningEnabled {
			p.VersionID = id.String()
		}
	} else {
		if err = id.DecodeString(p.VersionID); err != nil {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
		}

		if _, err = n.objectHead(ctx, p.BktInfo, id); err != nil {
			var errNotFound *apistatus.ObjectNotFound

			if errors.As(err, &errNotFound) {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
			}

			return nil, fmt.Errorf("head version %s: %w", p.VersionID, err)
		}

		hasTags, hasLocks, err = n.searchTagsAndLocksInNeoFS(ctx, p.BktInfo, owner, p.Object, p.VersionID)
		if err != nil {
			return nil, err
		}
	}

	if hasTags {
		tagPrm := &GetObjectTaggingParams{
			ObjectVersion: &ObjectVersion{
				BktInfo:    p.BktInfo,
				ObjectName: p.Object,
				VersionID:  p.VersionID,
			},
		}

		_, tagSet, err = n.GetObjectTagging(ctx, tagPrm)
		if err != nil {
			if !errors.Is(err, ErrNodeNotFound) {
				return nil, fmt.Errorf("get tags: %w", err)
			}
		}
	}

	if hasLocks {
		lockInfo, err = n.getLockDataFromObjects(ctx, p.BktInfo, p.Object, p.VersionID)
		if err != nil {
			if !errors.Is(err, ErrNodeNotFound) {
				return nil, fmt.Errorf("get locks: %w", err)
			}
		}
	}

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("get object",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", p.BktInfo.Name),
		zap.Stringer("cid", p.BktInfo.CID),
		zap.String("object", p.Object),
		zap.Stringer("oid", id))

	return &data.ComprehensiveObjectInfo{
		ID:       id,
		TagSet:   tagSet,
		LockInfo: lockInfo,
	}, nil
}

// GetIDForVersioningContainer returns actual oid.ID for object in versioned container.
func (n *layer) GetIDForVersioningContainer(ctx context.Context, p *ShortInfoParams) (oid.ID, error) {
	var (
		filters             = make(object.SearchFilters, 0, 3)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.FilterCreationEpoch,
			object.AttributeTimestamp,
			attrS3DeleteMarker,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, p.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(object.AttributeFilePath, p.Object, object.MatchStringEqual)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	filters.AddFilter(s3headers.MetaType, "", object.MatchNotPresent)

	if !p.FindNullVersion {
		filters.AddFilter(attrS3VersioningState, data.VersioningEnabled, object.MatchStringEqual)
	}

	ids, err := n.neoFS.SearchObjectsV2(ctx, p.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return oid.ID{}, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return oid.ID{}, fmt.Errorf("search objects: %w", err)
	}

	if len(ids) == 0 {
		return oid.ID{}, ErrNodeNotFound
	}

	var searchResults = make([]versioningContainerIDSearchResult, 0, len(ids))

	for _, item := range ids {
		if len(item.Attributes) != len(returningAttributes) {
			return oid.ID{}, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = versioningContainerIDSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationEpoch, err = strconv.ParseUint(item.Attributes[1], 10, 64)
			if err != nil {
				return oid.ID{}, fmt.Errorf("invalid creation epoch %s: %w", item.Attributes[1], err)
			}
		}

		if item.Attributes[2] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[2], 10, 64)
			if err != nil {
				return oid.ID{}, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[2], err)
			}
		}

		psr.IsDeleteMarker = item.Attributes[3] != ""

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b versioningContainerIDSearchResult) int {
		if c := cmp.Compare(b.CreationEpoch, a.CreationEpoch); c != 0 { // reverse order.
			return c
		}

		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	slices.SortFunc(searchResults, sortFunc)

	if searchResults[0].IsDeleteMarker {
		return oid.ID{}, ErrNodeNotFound
	}

	return searchResults[0].ID, nil
}

// CopyObject from one bucket into another bucket.
func (n *layer) CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ExtendedObjectInfo, error) {
	pr, pw := io.Pipe()

	go func() {
		err := n.GetObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObject,
			Writer:     pw,
			Range:      p.Range,
			BucketInfo: p.ScrBktInfo,
			Encryption: p.Encryption,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	return n.PutObject(ctx, &PutObjectParams{
		BktInfo:      p.DstBktInfo,
		Object:       p.DstObject,
		Size:         p.SrcSize,
		Reader:       pr,
		Header:       p.Header,
		Encryption:   p.Encryption,
		CopiesNumber: p.CopiesNuber,
	})
}

func (n *layer) deleteObject(ctx context.Context, bkt *data.BucketInfo, settings *data.BucketSettings, obj *VersionedObject) *VersionedObject {
	if settings.VersioningEnabled() {
		if len(obj.VersionID) > 0 {
			var deleteOID oid.ID

			if obj.VersionID == data.UnversionedObjectVersionID {
				versions, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, obj.Name, true)
				if err != nil {
					obj.Error = fmt.Errorf("search versions: %w", err)
					if errors.Is(err, ErrNodeNotFound) {
						obj.Error = nil
					}

					return obj
				}

				if len(versions) == 0 {
					obj.Error = nil
					return obj
				}

				for _, version := range versions {
					if obj.Error = n.objectDelete(ctx, bkt, version.ID); obj.Error != nil {
						return obj
					}
				}
			} else {
				if err := deleteOID.DecodeString(obj.VersionID); err != nil {
					obj.Error = fmt.Errorf("decode version: %w", err)
					return obj
				}

				if obj.Error = n.objectDelete(ctx, bkt, deleteOID); obj.Error != nil {
					return obj
				}
			}
		} else {
			var markerOID oid.ID
			markerOID, obj.Error = n.putDeleteMarker(ctx, bkt, obj.Name)
			obj.DeleteMarkVersion = markerOID.EncodeToString()
		}

		n.cache.DeleteObjectName(bkt.CID, bkt.Name, obj.Name)
		return obj
	}

	if settings.VersioningSuspended() {
		obj.VersionID = data.UnversionedObjectVersionID

		versions, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, obj.Name, true)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				obj.Error = nil
			} else {
				obj.Error = fmt.Errorf("search versions: %w", err)
			}

			return obj
		}

		for _, version := range versions {
			if obj.Error = n.objectDelete(ctx, bkt, version.ID); obj.Error != nil {
				return obj
			}
		}

		return obj
	}

	versions, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, obj.Name, false)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			obj.Error = nil
		} else {
			obj.Error = fmt.Errorf("search versions: %w", err)
		}

		return obj
	}

	if obj.VersionID == "" {
		for _, ver := range versions {
			if obj.Error = n.objectDelete(ctx, bkt, ver.ID); obj.Error != nil {
				n.log.Error("could not delete object", zap.Error(obj.Error), zap.Stringer("oid", ver.ID))
				if isErrObjectAlreadyRemoved(obj.Error) {
					obj.Error = nil
					continue
				}

				return obj
			}
		}
	} else {
		for _, ver := range versions {
			if ver.ID.EncodeToString() == obj.VersionID {
				if obj.Error = n.objectDelete(ctx, bkt, ver.ID); obj.Error != nil {
					return obj
				}

				return obj
			}
		}
	}

	n.cache.DeleteObjectName(bkt.CID, bkt.Name, obj.Name)

	return obj
}

func isErrObjectAlreadyRemoved(err error) bool {
	var (
		ol  apistatus.ObjectAlreadyRemoved
		olp *apistatus.ObjectAlreadyRemoved
	)
	switch {
	case errors.As(err, &ol), errors.As(err, &olp):
		return true
	default:
		return strings.Contains(err.Error(), "object already removed")
	}
}

// DeleteObjects from the storage.
func (n *layer) DeleteObjects(ctx context.Context, p *DeleteObjectParams) []*VersionedObject {
	for i, obj := range p.Objects {
		p.Objects[i] = n.deleteObject(ctx, p.BktInfo, p.Settings, obj)
	}

	return p.Objects
}

func (n *layer) CreateBucket(ctx context.Context, p *CreateBucketParams) (*data.BucketInfo, error) {
	bktInfo, err := n.GetBucketInfo(ctx, p.Name)
	if err != nil {
		if s3errors.IsS3Error(err, s3errors.ErrNoSuchBucket) {
			return n.createContainer(ctx, p)
		}
		return nil, err
	}

	if p.SessionContainerCreation != nil && session.IssuedBy(*p.SessionContainerCreation, bktInfo.Owner) {
		return nil, s3errors.GetAPIError(s3errors.ErrBucketAlreadyOwnedByYou)
	}

	return nil, s3errors.GetAPIError(s3errors.ErrBucketAlreadyExists)
}

func (n *layer) ResolveBucket(ctx context.Context, name string) (cid.ID, error) {
	cnrID, err := cid.DecodeString(name)
	if err != nil {
		if cnrID, err = n.resolver.ResolveCID(ctx, name); err != nil {
			return cid.ID{}, err
		}

		reqInfo := api.GetReqInfo(ctx)
		n.log.Info("resolve bucket", zap.String("reqId", reqInfo.RequestID), zap.String("bucket", name), zap.Stringer("cid", cnrID))
	}

	return cnrID, nil
}

func (n *layer) DeleteBucket(ctx context.Context, p *DeleteBucketParams) error {
	objects, err := n.searchAllVersionsInNeoFS(ctx, p.BktInfo, p.BktInfo.Owner, "", false)
	if err != nil {
		if !errors.Is(err, ErrNodeNotFound) {
			return err
		}
	}

	// there are only Regular objects in slice.
	if len(objects) != 0 {
		return s3errors.GetAPIError(s3errors.ErrBucketNotEmpty)
	}

	n.cache.DeleteBucket(p.BktInfo.Name)
	return n.neoFS.DeleteContainer(ctx, p.BktInfo.CID, p.SessionToken)
}

func (n *layer) putDeleteMarker(ctx context.Context, bktInfo *data.BucketInfo, objectName string) (oid.ID, error) {
	var (
		ts     = strconv.FormatInt(time.Now().Unix(), 10)
		params = PutObjectParams{
			BktInfo: bktInfo,
			Object:  objectName,
			Reader:  bytes.NewReader(nil),
			Header: map[string]string{
				attrS3DeleteMarker: ts,
			},
		}
	)

	extendedObjectInfo, err := n.PutObject(ctx, &params)
	if err != nil {
		return oid.ID{}, fmt.Errorf("save delete marker object: %w", err)
	}

	return extendedObjectInfo.ObjectInfo.ID, nil
}
