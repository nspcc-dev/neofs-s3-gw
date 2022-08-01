package layer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	errorsStd "errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sio"
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
		Encryption EncryptionParams
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

	// AES256Key is a key for encryption.
	AES256Key [32]byte

	EncryptionParams struct {
		enabled     bool
		customerKey AES256Key
	}

	// PutObjectParams stores object put request parameters.
	PutObjectParams struct {
		BktInfo    *data.BucketInfo
		Object     string
		Size       int64
		Reader     io.Reader
		Header     map[string]string
		Lock       *data.ObjectLock
		Encryption EncryptionParams
	}

	DeleteObjectParams struct {
		BktInfo  *data.BucketInfo
		Objects  []*VersionedObject
		Settings *data.BucketSettings
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
		Encryption EncryptionParams
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
		GetObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error)
		GetExtendedObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ExtendedObjectInfo, error)

		GetLockInfo(ctx context.Context, obj *ObjectVersion) (*data.LockInfo, error)
		PutLockInfo(ctx context.Context, p *ObjectVersion, lock *data.ObjectLock) error

		GetBucketTagging(ctx context.Context, cnrID cid.ID) (map[string]string, error)
		PutBucketTagging(ctx context.Context, cnrID cid.ID, tagSet map[string]string) error
		DeleteBucketTagging(ctx context.Context, cnrID cid.ID) error

		GetObjectTagging(ctx context.Context, p *ObjectVersion) (string, map[string]string, error)
		PutObjectTagging(ctx context.Context, p *ObjectVersion, tagSet map[string]string) (*data.NodeVersion, error)
		DeleteObjectTagging(ctx context.Context, p *ObjectVersion) (*data.NodeVersion, error)

		PutObject(ctx context.Context, p *PutObjectParams) (*data.ObjectInfo, error)

		CopyObject(ctx context.Context, p *CopyObjectParams) (*data.ObjectInfo, error)

		ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error)
		ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error)
		ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error)

		DeleteObjects(ctx context.Context, p *DeleteObjectParams) []*VersionedObject

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

	AESEncryptionAlgorithm       = "AES256"
	AESKeySize                   = 32
	AttributeEncryptionAlgorithm = api.NeoFSSystemMetadataPrefix + "Algorithm"
	AttributeDecryptedSize       = api.NeoFSSystemMetadataPrefix + "Decrypted-Size"
	AttributeHMACSalt            = api.NeoFSSystemMetadataPrefix + "HMAC-Salt"
	AttributeHMACKey             = api.NeoFSSystemMetadataPrefix + "HMAC-Key"
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

func (f MsgHandlerFunc) HandleMessage(ctx context.Context, msg *nats.Msg) error {
	return f(ctx, msg)
}

// NewEncryptionParams create new params to encrypt with provided key.
func NewEncryptionParams(key AES256Key) EncryptionParams {
	return EncryptionParams{
		enabled:     true,
		customerKey: key,
	}
}

// Key returns encryption key as slice.
func (p EncryptionParams) Key() []byte {
	return p.customerKey[:]
}

// AESKey returns encryption key.
func (p EncryptionParams) AESKey() AES256Key {
	return p.customerKey
}

// Enabled returns true if key isn't empty.
func (p EncryptionParams) Enabled() bool {
	return p.enabled
}

// HMAC compute salted HMAC.
func (p EncryptionParams) HMAC() ([]byte, []byte, error) {
	mac := hmac.New(sha256.New, p.Key())

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, errorsStd.New("failed to init create salt")
	}

	mac.Write(salt)
	return mac.Sum(nil), salt, nil
}

// MatchObjectEncryption check if encryption params are valid for provided object.
func (p EncryptionParams) MatchObjectEncryption(encInfo data.EncryptionInfo) error {
	if p.Enabled() != encInfo.Enabled {
		return errorsStd.New("invalid encryption view")
	}

	if !encInfo.Enabled {
		return nil
	}

	hmacSalt, err := hex.DecodeString(encInfo.HMACSalt)
	if err != nil {
		return fmt.Errorf("invalid hmacSalt '%s': %w", encInfo.HMACSalt, err)
	}

	hmacKey, err := hex.DecodeString(encInfo.HMACKey)
	if err != nil {
		return fmt.Errorf("invalid hmacKey '%s': %w", encInfo.HMACKey, err)
	}

	mac := hmac.New(sha256.New, p.Key())
	mac.Write(hmacSalt)
	expectedHmacKey := mac.Sum(nil)
	if !bytes.Equal(expectedHmacKey, hmacKey) {
		return errorsStd.New("mismatched hmac key")
	}

	return nil
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

func formEncryptedParts(header string) ([]EncryptedPart, error) {
	partInfos := strings.Split(header, ",")
	result := make([]EncryptedPart, len(partInfos))

	for i, partInfo := range partInfos {
		part, err := parseCompletedPartHeader(partInfo)
		if err != nil {
			return nil, err
		}

		encPartSize, err := sio.EncryptedSize(uint64(part.Size))
		if err != nil {
			return nil, fmt.Errorf("compute encrypted size: %w", err)
		}

		result[i] = EncryptedPart{
			Part:          *part,
			EncryptedSize: int64(encPartSize),
		}
	}

	return result, nil
}

type decrypter struct {
	reader      io.Reader
	decReader   io.Reader
	parts       []EncryptedPart
	currentPart int
	encryption  EncryptionParams

	rangeParam *RangeParams

	partDataRemain  int64
	encPartRangeLen int64

	seqNumber uint64
	decLen    int64
	skipLen   uint64

	ln  uint64
	off uint64
}

func (d decrypter) decLength() int64 {
	return d.decLen
}

func (d decrypter) encLength() uint64 {
	return d.ln
}

func (d decrypter) encOffset() uint64 {
	return d.off
}

func getDecryptReader(p *GetObjectParams) (*decrypter, error) {
	if !p.Encryption.Enabled() {
		return nil, errorsStd.New("couldn't create decrypter with disabled encryption")
	}

	rangeParam := p.Range

	var err error
	var parts []EncryptedPart
	header := p.ObjectInfo.Headers[UploadCompletedParts]
	if len(header) != 0 {
		parts, err = formEncryptedParts(header)
		if err != nil {
			return nil, fmt.Errorf("form parts: %w", err)
		}
		if rangeParam == nil {
			decSizeHeader := p.ObjectInfo.Headers[AttributeDecryptedSize]
			size, err := strconv.ParseUint(decSizeHeader, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse dec size header '%s': %w", decSizeHeader, err)
			}
			rangeParam = &RangeParams{
				Start: 0,
				End:   size - 1,
			}
		}
	} else {
		decSize, err := sio.DecryptedSize(uint64(p.ObjectInfo.Size))
		if err != nil {
			return nil, fmt.Errorf("compute decrypted size: %w", err)
		}

		parts = []EncryptedPart{{
			Part:          Part{Size: int64(decSize)},
			EncryptedSize: p.ObjectInfo.Size,
		}}
	}

	if rangeParam != nil && rangeParam.Start > rangeParam.End {
		return nil, fmt.Errorf("invalid range: %d %d", rangeParam.Start, rangeParam.End)
	}

	decReader := &decrypter{
		parts:      parts,
		rangeParam: rangeParam,
		encryption: p.Encryption,
	}

	decReader.initRangeParams()

	return decReader, nil
}

const (
	blockSize     = 1 << 16 // 64KB
	fullBlockSize = blockSize + 32
)

func (d *decrypter) initRangeParams() {
	d.partDataRemain = d.parts[d.currentPart].Size
	d.encPartRangeLen = d.parts[d.currentPart].EncryptedSize
	if d.rangeParam == nil {
		d.decLen = d.partDataRemain
		d.ln = uint64(d.encPartRangeLen)
		return
	}

	start, end := d.rangeParam.Start, d.rangeParam.End

	var sum, encSum uint64
	var partStart int
	for i, part := range d.parts {
		if start < sum+uint64(part.Size) {
			partStart = i
			break
		}
		sum += uint64(part.Size)
		encSum += uint64(part.EncryptedSize)
	}

	d.skipLen = (start - sum) % blockSize
	d.seqNumber = (start - sum) / blockSize
	encOffPart := d.seqNumber * fullBlockSize
	d.off = encSum + encOffPart
	d.encPartRangeLen = d.encPartRangeLen - int64(encOffPart)
	d.partDataRemain = d.partDataRemain + int64(sum-start)

	var partEnd int
	for i, part := range d.parts[partStart:] {
		index := partStart + i
		if end < sum+uint64(part.Size) {
			partEnd = index
			break
		}
		sum += uint64(part.Size)
		encSum += uint64(part.EncryptedSize)
	}

	payloadPartEnd := (end - sum) / blockSize
	endEnc := encSum + (payloadPartEnd+1)*fullBlockSize

	endPartEnc := encSum + uint64(d.parts[partEnd].EncryptedSize)
	if endPartEnc < endEnc {
		endEnc = endPartEnc
	}
	d.ln = endEnc - d.off
	d.decLen = int64(end - start + 1)

	if int64(d.ln) < d.encPartRangeLen {
		d.encPartRangeLen = int64(d.ln)
	}
	if d.decLen < d.partDataRemain {
		d.partDataRemain = d.decLen
	}
}

func (d *decrypter) updateRangeParams() {
	d.partDataRemain = d.parts[d.currentPart].Size
	d.encPartRangeLen = d.parts[d.currentPart].EncryptedSize
	d.seqNumber = 0
	d.skipLen = 0
}

func (d *decrypter) Read(p []byte) (int, error) {
	if int64(len(p)) < d.partDataRemain {
		n, err := d.decReader.Read(p)
		if err != nil {
			return n, err
		}
		d.partDataRemain -= int64(n)
		return n, nil
	}

	n1, err := io.ReadFull(d.decReader, p[:d.partDataRemain])
	if err != nil {
		return n1, err
	}

	d.currentPart++
	if d.currentPart == len(d.parts) {
		return n1, io.EOF
	}

	d.updateRangeParams()

	err = d.initNextDecReader()
	if err != nil {
		return n1, err
	}

	n2, err := d.decReader.Read(p[n1:])
	if err != nil {
		return n1 + n2, err
	}

	d.partDataRemain -= int64(n2)

	return n1 + n2, nil
}

func (d *decrypter) SetReader(r io.Reader) error {
	d.reader = r
	return d.initNextDecReader()
}

func (d *decrypter) initNextDecReader() error {
	if d.reader == nil {
		return errorsStd.New("reader isn't set")
	}

	r, err := sio.DecryptReader(io.LimitReader(d.reader, d.encPartRangeLen),
		sio.Config{
			MinVersion:     sio.Version20,
			SequenceNumber: uint32(d.seqNumber),
			Key:            d.encryption.Key(),
			CipherSuites:   []byte{sio.AES_256_GCM},
		})
	if err != nil {
		return fmt.Errorf("couldn't create decrypter: %w", err)
	}

	if d.skipLen > 0 {
		if _, err = io.CopyN(io.Discard, r, int64(d.skipLen)); err != nil {
			return fmt.Errorf("couldn't skip some bytes: %w", err)
		}
	}
	d.decReader = r

	return nil
}

// GetObject from storage.
func (n *layer) GetObject(ctx context.Context, p *GetObjectParams) error {
	var params getParams

	params.oid = p.ObjectInfo.ID
	params.bktInfo = p.BucketInfo

	var decReader *decrypter
	if p.Encryption.Enabled() {
		var err error
		decReader, err = getDecryptReader(p)
		if err != nil {
			return fmt.Errorf("creating decrypter: %w", err)
		}
		params.off = decReader.encOffset()
		params.ln = decReader.encLength()
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
		r = io.LimitReader(decReader, decReader.decLength())
	}

	// copy full payload
	written, err := io.CopyBuffer(p.Writer, r, buf)
	if err != nil {
		return fmt.Errorf("copy object payload written: '%d', decLength: '%d', params.ln: '%d' : %w", written, decReader.decLength(), params.ln, err)
	}

	return nil
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
			Encryption: p.Encryption,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	return n.PutObject(ctx, &PutObjectParams{
		BktInfo:    p.DstBktInfo,
		Object:     p.DstObject,
		Size:       p.SrcSize,
		Reader:     pr,
		Header:     p.Header,
		Encryption: p.Encryption,
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

func (n *layer) deleteObject(ctx context.Context, bkt *data.BucketInfo, settings *data.BucketSettings, obj *VersionedObject) *VersionedObject {
	if len(obj.VersionID) != 0 || settings.Unversioned() {
		var nodeVersion *data.NodeVersion
		if nodeVersion, obj.Error = n.getNodeVersionToDelete(ctx, bkt, obj); obj.Error != nil {
			return dismissNotFoundError(obj)
		}

		if obj.DeleteMarkVersion, obj.Error = n.removeOldVersion(ctx, bkt, nodeVersion, obj); obj.Error != nil {
			return obj
		}

		obj.Error = n.treeService.RemoveVersion(ctx, bkt.CID, nodeVersion.ID)
		n.listsCache.CleanCacheEntriesContainingObject(obj.Name, bkt.CID)
		return obj
	}

	var newVersion *data.NodeVersion

	if settings.VersioningSuspended() {
		obj.VersionID = data.UnversionedObjectVersionID

		var nodeVersion *data.NodeVersion
		if nodeVersion, obj.Error = n.getNodeVersionToDelete(ctx, bkt, obj); obj.Error != nil {
			return dismissNotFoundError(obj)
		}

		if obj.DeleteMarkVersion, obj.Error = n.removeOldVersion(ctx, bkt, nodeVersion, obj); obj.Error != nil {
			return obj
		}
	}

	randOID, err := getRandomOID()
	if err != nil {
		obj.Error = fmt.Errorf("couldn't get random oid: %w", err)
		return obj
	}

	obj.DeleteMarkVersion = randOID.EncodeToString()

	newVersion = &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			OID:      randOID,
			FilePath: obj.Name,
		},
		DeleteMarker: &data.DeleteMarkerInfo{
			Created: time.Now(),
			Owner:   n.Owner(ctx),
		},
		IsUnversioned: settings.VersioningSuspended(),
	}

	if obj.Error = n.treeService.AddVersion(ctx, bkt.CID, newVersion); obj.Error != nil {
		return obj
	}

	n.namesCache.Delete(bkt.Name + "/" + obj.Name)
	n.listsCache.CleanCacheEntriesContainingObject(obj.Name, bkt.CID)

	return obj
}

func dismissNotFoundError(obj *VersionedObject) *VersionedObject {
	if errors.IsS3Error(obj.Error, errors.ErrNoSuchKey) ||
		errors.IsS3Error(obj.Error, errors.ErrNoSuchVersion) {
		obj.Error = nil
	}

	return obj
}

func (n *layer) getNodeVersionToDelete(ctx context.Context, bkt *data.BucketInfo, obj *VersionedObject) (*data.NodeVersion, error) {
	objVersion := &ObjectVersion{
		BktInfo:               bkt,
		ObjectName:            obj.Name,
		VersionID:             obj.VersionID,
		NoErrorOnDeleteMarker: true,
	}

	return n.getNodeVersion(ctx, objVersion)
}

func (n *layer) removeOldVersion(ctx context.Context, bkt *data.BucketInfo, nodeVersion *data.NodeVersion, obj *VersionedObject) (string, error) {
	if nodeVersion.IsDeleteMarker() {
		return obj.VersionID, nil
	}

	return "", n.objectDelete(ctx, bkt, nodeVersion.OID)
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
	nodeVersions, err := n.bucketNodeVersions(ctx, p.BktInfo, "")
	if err != nil {
		return err
	}
	if len(nodeVersions) != 0 {
		return errors.GetAPIError(errors.ErrBucketNotEmpty)
	}

	n.bucketCache.Delete(p.BktInfo.Name)
	return n.neoFS.DeleteContainer(ctx, p.BktInfo.CID, p.SessionToken)
}
