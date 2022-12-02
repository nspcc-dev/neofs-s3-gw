package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/sio"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	s3errors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

const (
	tagPrefix = "S3-Tag-"

	AESEncryptionAlgorithm       = "AES256"
	AESKeySize                   = 32
	AttributeEncryptionAlgorithm = api.NeoFSSystemMetadataPrefix + "Algorithm"
	AttributeDecryptedSize       = api.NeoFSSystemMetadataPrefix + "Decrypted-Size"
	AttributeHMACSalt            = api.NeoFSSystemMetadataPrefix + "HMAC-Salt"
	AttributeHMACKey             = api.NeoFSSystemMetadataPrefix + "HMAC-Key"

	AttributeNeofsCopiesNumber = "neofs-copies-number" // such formate to match X-Amz-Meta-Neofs-Copies-Number header

	UploadIDAttributeName         = "S3-Upload-Id"
	UploadPartNumberAttributeName = "S3-Upload-Part-Number"
	UploadCompletedParts          = "S3-Completed-Parts"

	metaPrefix = "meta-"
	aclPrefix  = "acl-"

	MaxSizeUploadsList  = 1000
	MaxSizePartsList    = 1000
	UploadMinPartNumber = 1
	UploadMaxPartNumber = 10000
	uploadMinSize       = 5 * 1048576    // 5MB
	uploadMaxSize       = 5 * 1073741824 // 5GB

	attributeLocationConstraint = ".s3-location-constraint"
	AttributeLockEnabled        = "LockEnabled"

	continuationToken = "<continuation-token>"
)

type (
	PutBucketNotificationConfigurationParams struct {
		RequestInfo   *api.ReqInfo
		BktInfo       *data.BucketInfo
		Configuration *data.NotificationConfiguration
		CopiesNumber  uint32
	}

	GetObjectTaggingParams struct {
		ObjectVersion *ObjectVersion

		// NodeVersion can be nil. If not nil we save one request to tree service.
		NodeVersion *data.NodeVersion // optional
	}

	PutObjectTaggingParams struct {
		ObjectVersion *ObjectVersion
		TagSet        map[string]string

		// NodeVersion can be nil. If not nil we save one request to tree service.
		NodeVersion *data.NodeVersion // optional
	}

	// BucketACL extends BucketInfo by eacl.Table.
	BucketACL struct {
		Info *data.BucketInfo
		EACL *eacl.Table
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
		BktInfo  *data.BucketInfo
		Settings *data.BucketSettings
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

	PutLockInfoParams struct {
		ObjVersion   *ObjectVersion
		NewLock      *data.ObjectLock
		CopiesNumber uint32
		NodeVersion  *data.NodeVersion // optional
	}
)

func (t *VersionedObject) String() string {
	return t.Name + ":" + t.VersionID
}

// getBucketACL returns bucket acl info by name.
func (h *handler) getBucketACL(ctx context.Context, bktInfo *data.BucketInfo) (*BucketACL, error) {
	eACL, err := h.neoFS.ContainerEACL(ctx, bktInfo.CID)
	if err != nil {
		return nil, fmt.Errorf("get container eacl: %w", err)
	}

	return &BucketACL{
		Info: bktInfo,
		EACL: eACL,
	}, nil
}

func (h *handler) putBucketACL(ctx context.Context, param *PutBucketACLParams) error {
	param.EACL.SetCID(param.BktInfo.CID)

	return h.neoFS.SetContainerEACL(ctx, *param.EACL, param.SessionToken)
}

// getObjectInfo returns meta information about the object.
func (h *handler) getObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ObjectInfo, error) {
	extendedObjectInfo, err := h.getExtendedObjectInfo(ctx, p)
	if err != nil {
		return nil, err
	}

	return extendedObjectInfo.ObjectInfo, nil
}

// getExtendedObjectInfo returns meta information and corresponding info from the tree service about the object.
func (h *handler) getExtendedObjectInfo(ctx context.Context, p *HeadObjectParams) (*data.ExtendedObjectInfo, error) {
	if len(p.VersionID) == 0 {
		return h.headLastVersionIfNotDeleted(ctx, p.BktInfo, p.Object)
	}

	return h.headVersion(ctx, p.BktInfo, p)
}

func (h *handler) headLastVersionIfNotDeleted(ctx context.Context, bkt *data.BucketInfo, objectName string) (*data.ExtendedObjectInfo, error) {
	owner := h.Owner(ctx)
	if extObjInfo := h.cache.GetLastObject(owner, bkt.Name, objectName); extObjInfo != nil {
		return extObjInfo, nil
	}

	node, err := h.treeService.GetLatestVersion(ctx, bkt, objectName)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
		}
		return nil, err
	}

	if node.IsDeleteMarker() {
		return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchKey)
	}

	meta, err := h.objectHead(ctx, bkt, node.OID)
	if err != nil {
		return nil, err
	}
	objInfo := objectInfoFromMeta(bkt, meta)

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: node,
	}

	h.cache.PutObjectWithName(owner, extObjInfo)

	return extObjInfo, nil
}

// objectHead returns all object's headers.
func (h *handler) objectHead(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) (*object.Object, error) {
	prm := PrmObjectRead{
		Container:  bktInfo.CID,
		Object:     idObj,
		WithHeader: true,
	}

	h.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	res, err := h.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	return res.Head, nil
}
func (h *handler) prepareAuthParameters(ctx context.Context, prm *PrmAuth, bktOwner user.ID) {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		if bktOwner.Equals(bearer.ResolveIssuer(*bd.Gate.BearerToken)) {
			prm.BearerToken = bd.Gate.BearerToken
			return
		}
	}

	prm.PrivateKey = &h.cfg.AnonKey.Key.PrivateKey
}

// Owner returns owner id from BearerToken (context) or from client owner.
func (h *handler) Owner(ctx context.Context) user.ID {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		return bearer.ResolveIssuer(*bd.Gate.BearerToken)
	}

	var ownerID user.ID
	user.IDFromKey(&ownerID, (ecdsa.PublicKey)(*h.EphemeralKey()))

	return ownerID
}

func (h *handler) EphemeralKey() *keys.PublicKey {
	return h.cfg.AnonKey.Key.PublicKey()
}

func (h *handler) headVersion(ctx context.Context, bkt *data.BucketInfo, p *HeadObjectParams) (*data.ExtendedObjectInfo, error) {
	var err error
	var foundVersion *data.NodeVersion
	if p.VersionID == data.UnversionedObjectVersionID {
		foundVersion, err = h.treeService.GetUnversioned(ctx, bkt, p.Object)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
			}
			return nil, err
		}
	} else {
		versions, err := h.treeService.GetVersions(ctx, bkt, p.Object)
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

	owner := h.Owner(ctx)
	if extObjInfo := h.cache.GetObject(owner, newAddress(bkt.CID, foundVersion.OID)); extObjInfo != nil {
		return extObjInfo, nil
	}

	meta, err := h.objectHead(ctx, bkt, foundVersion.OID)
	if err != nil {
		if client.IsErrObjectNotFound(err) {
			return nil, apiErrors.GetAPIError(apiErrors.ErrNoSuchVersion)
		}
		return nil, err
	}
	objInfo := objectInfoFromMeta(bkt, meta)

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: foundVersion,
	}

	h.cache.PutObject(owner, extObjInfo)

	return extObjInfo, nil
}

func newAddress(cnr cid.ID, obj oid.ID) oid.Address {
	var addr oid.Address
	addr.SetContainer(cnr)
	addr.SetObject(obj)
	return addr
}

// getBoxData  extracts accessbox.Box from context.
func getBoxData(ctx context.Context) (*accessbox.Box, error) {
	boxData, ok := ctx.Value(api.BoxData).(*accessbox.Box)
	if !ok || boxData == nil {
		return nil, fmt.Errorf("couldn't get box data from context")
	}

	if boxData.Gate == nil {
		boxData.Gate = &accessbox.GateData{}
	}
	return boxData, nil
}

func (h *handler) getBucketSettings(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	owner := h.Owner(ctx)
	if settings := h.cache.GetSettings(owner, bktInfo); settings != nil {
		return settings, nil
	}

	settings, err := h.treeService.GetSettingsNode(ctx, bktInfo)
	if err != nil {
		if !errors.Is(err, ErrNodeNotFound) {
			return nil, err
		}
		settings = &data.BucketSettings{Versioning: data.VersioningUnversioned}
	}

	h.cache.PutSettings(owner, bktInfo, settings)

	return settings, nil
}

// copyObject from one bucket into another bucket.
func (h *handler) copyObject(ctx context.Context, p *CopyObjectParams) (*data.ExtendedObjectInfo, error) {
	pr, pw := io.Pipe()

	go func() {
		err := h.getObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObject,
			Writer:     pw,
			Range:      p.Range,
			BucketInfo: p.ScrBktInfo,
			Encryption: p.Encryption,
		})

		if err = pw.CloseWithError(err); err != nil {
			h.log.Error("could not get object", zap.Error(err))
		}
	}()

	return h.putObject(ctx, &PutObjectParams{
		BktInfo:      p.DstBktInfo,
		Object:       p.DstObject,
		Size:         p.SrcSize,
		Reader:       pr,
		Header:       p.Header,
		Encryption:   p.Encryption,
		CopiesNumber: p.CopiesNuber,
	})
}

// getObject from storage.
func (h *handler) getObject(ctx context.Context, p *GetObjectParams) error {
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

	payload, err := h.initObjectPayloadReader(ctx, params)
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

// putObject stores object into NeoFS, took payload from io.Reader.
func (h *handler) putObject(ctx context.Context, p *PutObjectParams) (*data.ExtendedObjectInfo, error) {
	owner := h.Owner(ctx)

	bktSettings, err := h.getBucketSettings(ctx, p.BktInfo)
	if err != nil {
		return nil, fmt.Errorf("couldn't get versioning settings object: %w", err)
	}

	newVersion := &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			FilePath: p.Object,
			Size:     p.Size,
		},
		IsUnversioned: !bktSettings.VersioningEnabled(),
	}

	r := p.Reader
	if p.Encryption.Enabled() {
		p.Header[AttributeDecryptedSize] = strconv.FormatInt(p.Size, 10)
		if err = addEncryptionHeaders(p.Header, p.Encryption); err != nil {
			return nil, fmt.Errorf("add encryption header: %w", err)
		}

		var encSize uint64
		if r, encSize, err = encryptionReader(p.Reader, uint64(p.Size), p.Encryption.Key()); err != nil {
			return nil, fmt.Errorf("create encrypter: %w", err)
		}
		p.Size = int64(encSize)
	}

	if r != nil {
		if len(p.Header[api.ContentType]) == 0 {
			if contentType := MimeByFilePath(p.Object); len(contentType) == 0 {
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
		Container:    p.BktInfo.CID,
		Creator:      owner,
		PayloadSize:  uint64(p.Size),
		Filepath:     p.Object,
		Payload:      r,
		CreationTime: TimeNow(ctx),
		CopiesNumber: p.CopiesNumber,
	}

	prm.Attributes = make([][2]string, 0, len(p.Header))

	for k, v := range p.Header {
		prm.Attributes = append(prm.Attributes, [2]string{k, v})
	}

	id, hash, err := h.objectPutAndHash(ctx, prm, p.BktInfo)
	if err != nil {
		return nil, err
	}

	newVersion.OID = id
	newVersion.ETag = hex.EncodeToString(hash)
	if newVersion.ID, err = h.treeService.AddVersion(ctx, p.BktInfo, newVersion); err != nil {
		return nil, fmt.Errorf("couldn't add new verion to tree service: %w", err)
	}

	if p.Lock != nil && (p.Lock.Retention != nil || p.Lock.LegalHold != nil) {
		putLockInfoPrms := &PutLockInfoParams{
			ObjVersion: &ObjectVersion{
				BktInfo:    p.BktInfo,
				ObjectName: p.Object,
				VersionID:  id.EncodeToString(),
			},
			NewLock:      p.Lock,
			CopiesNumber: p.CopiesNumber,
			NodeVersion:  newVersion, // provide new version to make one less tree service call in PutLockInfo
		}

		if err = h.putLockInfo(ctx, putLockInfoPrms); err != nil {
			return nil, err
		}
	}

	h.cache.CleanListCacheEntriesContainingObject(p.Object, p.BktInfo.CID)

	objInfo := &data.ObjectInfo{
		ID:  id,
		CID: p.BktInfo.CID,

		Owner:       owner,
		Bucket:      p.BktInfo.Name,
		Name:        p.Object,
		Size:        p.Size,
		Created:     prm.CreationTime,
		Headers:     p.Header,
		ContentType: p.Header[api.ContentType],
		HashSum:     newVersion.ETag,
	}

	extendedObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: newVersion,
	}

	h.cache.PutObjectWithName(owner, extendedObjInfo)

	return extendedObjInfo, nil
}

// objectGet returns an object with payload in the object.
func (h *handler) objectGet(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (*object.Object, error) {
	prm := PrmObjectRead{
		Container:   bktInfo.CID,
		Object:      objID,
		WithHeader:  true,
		WithPayload: true,
	}

	h.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	res, err := h.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	return res.Head, nil
}

// objectDelete puts tombstone object into neofs.
func (h *handler) objectDelete(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) error {
	prm := PrmObjectDelete{
		Container: bktInfo.CID,
		Object:    idObj,
	}

	h.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	h.cache.DeleteObject(newAddress(bktInfo.CID, idObj))

	return h.neoFS.DeleteObject(ctx, prm)
}

func (h *handler) getObjectTagging(ctx context.Context, p *GetObjectTaggingParams) (string, map[string]string, error) {
	var err error
	owner := h.Owner(ctx)

	if len(p.ObjectVersion.VersionID) != 0 && p.ObjectVersion.VersionID != data.UnversionedObjectVersionID {
		if tags := h.cache.GetTagging(owner, objectTaggingCacheKey(p.ObjectVersion)); tags != nil {
			return p.ObjectVersion.VersionID, tags, nil
		}
	}

	nodeVersion := p.NodeVersion
	if nodeVersion == nil {
		nodeVersion, err = h.getNodeVersionFromCacheOrNeofs(ctx, p.ObjectVersion)
		if err != nil {
			return "", nil, err
		}
	}
	p.ObjectVersion.VersionID = nodeVersion.OID.EncodeToString()

	if tags := h.cache.GetTagging(owner, objectTaggingCacheKey(p.ObjectVersion)); tags != nil {
		return p.ObjectVersion.VersionID, tags, nil
	}

	tags, err := h.treeService.GetObjectTagging(ctx, p.ObjectVersion.BktInfo, nodeVersion)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return "", nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}
		return "", nil, err
	}

	h.cache.PutTagging(owner, objectTaggingCacheKey(p.ObjectVersion), tags)

	return p.ObjectVersion.VersionID, tags, nil
}

func (h *handler) putObjectTagging(ctx context.Context, p *PutObjectTaggingParams) (nodeVersion *data.NodeVersion, err error) {
	nodeVersion = p.NodeVersion
	if nodeVersion == nil {
		nodeVersion, err = h.getNodeVersionFromCacheOrNeofs(ctx, p.ObjectVersion)
		if err != nil {
			return nil, err
		}
	}
	p.ObjectVersion.VersionID = nodeVersion.OID.EncodeToString()

	err = h.treeService.PutObjectTagging(ctx, p.ObjectVersion.BktInfo, nodeVersion, p.TagSet)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}
		return nil, err
	}

	h.cache.PutTagging(h.Owner(ctx), objectTaggingCacheKey(p.ObjectVersion), p.TagSet)

	return nodeVersion, nil
}

func (h *handler) deleteBucket(ctx context.Context, p *DeleteBucketParams) error {
	nodeVersions, err := h.bucketNodeVersions(ctx, p.BktInfo, "")
	if err != nil {
		return err
	}
	if len(nodeVersions) != 0 {
		return s3errors.GetAPIError(s3errors.ErrBucketNotEmpty)
	}

	h.cache.DeleteBucket(p.BktInfo.Name)
	return h.neoFS.DeleteContainer(ctx, p.BktInfo.CID, p.SessionToken)
}

func (h *handler) bucketNodeVersions(ctx context.Context, bkt *data.BucketInfo, prefix string) ([]*data.NodeVersion, error) {
	var err error

	owner := h.Owner(ctx)
	cacheKey := cache.CreateObjectsListCacheKey(bkt.CID, prefix, false)
	nodeVersions := h.cache.GetList(owner, cacheKey)

	if nodeVersions == nil {
		nodeVersions, err = h.treeService.GetAllVersionsByPrefix(ctx, bkt, prefix)
		if err != nil {
			return nil, fmt.Errorf("get all versions from tree service: %w", err)
		}

		h.cache.PutList(owner, cacheKey, nodeVersions)
	}

	return nodeVersions, nil
}

func (h *handler) deleteObjectTagging(ctx context.Context, p *ObjectVersion) (*data.NodeVersion, error) {
	version, err := h.getNodeVersion(ctx, p)
	if err != nil {
		return nil, err
	}

	err = h.treeService.DeleteObjectTagging(ctx, p.BktInfo, version)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}
		return nil, err
	}

	p.VersionID = version.OID.EncodeToString()

	h.cache.DeleteTagging(objectTaggingCacheKey(p))

	return version, nil
}

func (h *handler) getBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error) {
	owner := h.Owner(ctx)

	if tags := h.cache.GetTagging(owner, bucketTaggingCacheKey(bktInfo.CID)); tags != nil {
		return tags, nil
	}

	tags, err := h.treeService.GetBucketTagging(ctx, bktInfo)
	if err != nil && !errors.Is(err, ErrNodeNotFound) {
		return nil, err
	}

	h.cache.PutTagging(owner, bucketTaggingCacheKey(bktInfo.CID), tags)

	return tags, nil
}

func (h *handler) putBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string) error {
	if err := h.treeService.PutBucketTagging(ctx, bktInfo, tagSet); err != nil {
		return err
	}

	h.cache.PutTagging(h.Owner(ctx), bucketTaggingCacheKey(bktInfo.CID), tagSet)

	return nil
}

func (h *handler) deleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error {
	h.cache.DeleteTagging(bucketTaggingCacheKey(bktInfo.CID))

	return h.treeService.DeleteBucketTagging(ctx, bktInfo)
}

func objectTaggingCacheKey(p *ObjectVersion) string {
	return ".tagset." + p.BktInfo.CID.EncodeToString() + "." + p.ObjectName + "." + p.VersionID
}

func bucketTaggingCacheKey(cnrID cid.ID) string {
	return ".tagset." + cnrID.EncodeToString()
}

func (h *handler) getNodeVersion(ctx context.Context, objVersion *ObjectVersion) (*data.NodeVersion, error) {
	var err error
	var version *data.NodeVersion

	if objVersion.VersionID == data.UnversionedObjectVersionID {
		version, err = h.treeService.GetUnversioned(ctx, objVersion.BktInfo, objVersion.ObjectName)
	} else if len(objVersion.VersionID) == 0 {
		version, err = h.treeService.GetLatestVersion(ctx, objVersion.BktInfo, objVersion.ObjectName)
	} else {
		versions, err2 := h.treeService.GetVersions(ctx, objVersion.BktInfo, objVersion.ObjectName)
		if err2 != nil {
			return nil, err2
		}
		for _, v := range versions {
			if v.OID.EncodeToString() == objVersion.VersionID {
				version = v
				break
			}
		}
		if version == nil {
			err = s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
		}
	}

	if err == nil && version.IsDeleteMarker() && !objVersion.NoErrorOnDeleteMarker || errors.Is(err, ErrNodeNotFound) {
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
	}

	return version, err
}

func (h *handler) getNodeVersionFromCache(owner user.ID, o *ObjectVersion) *data.NodeVersion {
	if len(o.VersionID) == 0 || o.VersionID == data.UnversionedObjectVersionID {
		return nil
	}

	var objID oid.ID
	if objID.DecodeString(o.VersionID) != nil {
		return nil
	}

	var addr oid.Address
	addr.SetContainer(o.BktInfo.CID)
	addr.SetObject(objID)

	extObjectInfo := h.cache.GetObject(owner, addr)
	if extObjectInfo == nil {
		return nil
	}

	return extObjectInfo.NodeVersion
}

// objectPutAndHash prepare auth parameters and invoke neofs.CreateObject.
// Returns object ID and payload sha256 hash.
func (h *handler) objectPutAndHash(ctx context.Context, prm PrmObjectCreate, bktInfo *data.BucketInfo) (oid.ID, []byte, error) {
	h.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)
	hash := sha256.New()
	prm.Payload = wrapReader(prm.Payload, 64*1024, func(buf []byte) {
		hash.Write(buf)
	})
	id, err := h.neoFS.CreateObject(ctx, prm)
	if err != nil {
		return oid.ID{}, nil, err
	}
	return id, hash.Sum(nil), nil
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

// TimeNow returns client time from request or time.Now().
func TimeNow(ctx context.Context) time.Time {
	if now, ok := ctx.Value(api.ClientTime).(time.Time); ok {
		return now
	}

	return time.Now()
}

// MimeByFilePath detect mime type by file path extension.
func MimeByFilePath(path string) string {
	ext := filepath.Ext(path)
	if len(ext) == 0 {
		return ""
	}
	return mime.TypeByExtension(ext)
}

func encryptionReader(r io.Reader, size uint64, key []byte) (io.Reader, uint64, error) {
	encSize, err := sio.EncryptedSize(size)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute enc size: %w", err)
	}

	r, err = sio.EncryptReader(r, sio.Config{MinVersion: sio.Version20, MaxVersion: sio.Version20, Key: key, CipherSuites: []byte{sio.AES_256_GCM}})
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't create encrypter: %w", err)
	}

	return r, encSize, nil
}

// initializes payload reader of the NeoFS object.
// Zero range corresponds to full payload (panics if only offset is set).
func (h *handler) initObjectPayloadReader(ctx context.Context, p getParams) (io.Reader, error) {
	prm := PrmObjectRead{
		Container:    p.bktInfo.CID,
		Object:       p.oid,
		WithPayload:  true,
		PayloadRange: [2]uint64{p.off, p.ln},
	}

	h.prepareAuthParameters(ctx, &prm.PrmAuth, p.bktInfo.Owner)

	res, err := h.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

type (
	UploadInfoParams struct {
		UploadID   string
		Bkt        *data.BucketInfo
		Key        string
		Encryption encryption.Params
	}

	CreateMultipartParams struct {
		Info         *UploadInfoParams
		Header       map[string]string
		Data         *UploadData
		CopiesNumber uint32
	}

	UploadData struct {
		TagSet     map[string]string
		ACLHeaders map[string]string
	}

	UploadPartParams struct {
		Info       *UploadInfoParams
		PartNumber int
		Size       int64
		Reader     io.Reader
	}

	UploadCopyParams struct {
		Info       *UploadInfoParams
		SrcObjInfo *data.ObjectInfo
		SrcBktInfo *data.BucketInfo
		PartNumber int
		Range      *RangeParams
	}

	CompleteMultipartParams struct {
		Info  *UploadInfoParams
		Parts []*CompletedPart
	}

	CompletedPart struct {
		ETag       string
		PartNumber int
	}

	EncryptedPart struct {
		Part
		EncryptedSize int64
	}

	Part struct {
		ETag         string
		LastModified string
		PartNumber   int
		Size         int64
	}

	ListMultipartUploadsParams struct {
		Bkt            *data.BucketInfo
		Delimiter      string
		EncodingType   string
		KeyMarker      string
		MaxUploads     int
		Prefix         string
		UploadIDMarker string
	}

	ListPartsParams struct {
		Info             *UploadInfoParams
		MaxParts         int
		PartNumberMarker int
	}

	ListPartsInfo struct {
		Parts                []*Part
		Owner                user.ID
		NextPartNumberMarker int
		IsTruncated          bool
	}

	ListMultipartUploadsInfo struct {
		Prefixes           []string
		Uploads            []*UploadInfo
		IsTruncated        bool
		NextKeyMarker      string
		NextUploadIDMarker string
	}
	UploadInfo struct {
		IsDir    bool
		Key      string
		UploadID string
		Owner    user.ID
		Created  time.Time
	}
)

func ParseCompletedPartHeader(hdr string) (*Part, error) {
	// partInfo[0] -- part number, partInfo[1] -- part size, partInfo[2] -- checksum
	partInfo := strings.Split(hdr, "-")
	if len(partInfo) != 3 {
		return nil, fmt.Errorf("invalid completed part header")
	}
	num, err := strconv.Atoi(partInfo[0])
	if err != nil {
		return nil, fmt.Errorf("invalid completed part number '%s': %w", partInfo[0], err)
	}
	size, err := strconv.Atoi(partInfo[1])
	if err != nil {
		return nil, fmt.Errorf("invalid completed part size '%s': %w", partInfo[1], err)
	}

	return &Part{
		ETag:       partInfo[2],
		PartNumber: num,
		Size:       int64(size),
	}, nil
}

// getBucketInfo returns bucket info by name.
func (h *handler) getBucketInfo(ctx context.Context, name string) (*data.BucketInfo, error) {
	name, err := url.QueryUnescape(name)
	if err != nil {
		return nil, fmt.Errorf("unescape bucket name: %w", err)
	}

	if bktInfo := h.cache.GetBucket(name); bktInfo != nil {
		return bktInfo, nil
	}

	containerID, err := h.ResolveBucket(ctx, name)
	if err != nil {
		h.log.Debug("bucket not found", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchBucket)
	}

	return h.containerInfo(ctx, containerID)
}
func (h *handler) ResolveBucket(ctx context.Context, name string) (cid.ID, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(name); err != nil {
		return h.resolver.Resolve(ctx, name)
	}

	return cnrID, nil
}

func (h *handler) containerInfo(ctx context.Context, idCnr cid.ID) (*data.BucketInfo, error) {
	var (
		err error
		res *container.Container
		rid = api.GetRequestID(ctx)
		log = h.log.With(zap.Stringer("cid", idCnr), zap.String("request_id", rid))

		info = &data.BucketInfo{
			CID:  idCnr,
			Name: idCnr.EncodeToString(),
		}
	)
	res, err = h.neoFS.Container(ctx, idCnr)
	if err != nil {
		log.Error("could not fetch container", zap.Error(err))

		if client.IsErrContainerNotFound(err) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchBucket)
		}
		return nil, fmt.Errorf("get neofs container: %w", err)
	}

	cnr := *res

	info.Owner = cnr.Owner()
	if domain := container.ReadDomain(cnr); domain.Name() != "" {
		info.Name = domain.Name()
	}
	info.Created = container.CreatedAt(cnr)
	info.LocationConstraint = cnr.Attribute(attributeLocationConstraint)

	attrLockEnabled := cnr.Attribute(AttributeLockEnabled)
	if len(attrLockEnabled) > 0 {
		info.ObjectLockEnabled, err = strconv.ParseBool(attrLockEnabled)
		if err != nil {
			log.Error("could not parse container object lock enabled attribute",
				zap.String("lock_enabled", attrLockEnabled),
				zap.Error(err),
			)
		}
	}

	h.cache.PutBucket(info)

	return info, nil
}

// deleteObjects from the storage.
func (h *handler) deleteObjects(ctx context.Context, p *DeleteObjectParams) []*VersionedObject {
	for i, obj := range p.Objects {
		p.Objects[i] = h.deleteObject(ctx, p.BktInfo, p.Settings, obj)
	}

	return p.Objects
}

func (h *handler) deleteObject(ctx context.Context, bkt *data.BucketInfo, settings *data.BucketSettings, obj *VersionedObject) *VersionedObject {
	if len(obj.VersionID) != 0 || settings.Unversioned() {
		var nodeVersion *data.NodeVersion
		if nodeVersion, obj.Error = h.getNodeVersionToDelete(ctx, bkt, obj); obj.Error != nil {
			return dismissNotFoundError(obj)
		}

		if obj.DeleteMarkVersion, obj.Error = h.removeOldVersion(ctx, bkt, nodeVersion, obj); obj.Error != nil {
			return obj
		}

		obj.Error = h.treeService.RemoveVersion(ctx, bkt, nodeVersion.ID)
		h.cache.CleanListCacheEntriesContainingObject(obj.Name, bkt.CID)
		return obj
	}

	var newVersion *data.NodeVersion

	if settings.VersioningSuspended() {
		obj.VersionID = data.UnversionedObjectVersionID

		var nodeVersion *data.NodeVersion
		if nodeVersion, obj.Error = h.getNodeVersionToDelete(ctx, bkt, obj); obj.Error != nil {
			return dismissNotFoundError(obj)
		}

		if obj.DeleteMarkVersion, obj.Error = h.removeOldVersion(ctx, bkt, nodeVersion, obj); obj.Error != nil {
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
			Created: TimeNow(ctx),
			Owner:   h.Owner(ctx),
		},
		IsUnversioned: settings.VersioningSuspended(),
	}

	if _, obj.Error = h.treeService.AddVersion(ctx, bkt, newVersion); obj.Error != nil {
		return obj
	}

	h.cache.DeleteObjectName(bkt.CID, bkt.Name, obj.Name)

	return obj
}

func (h *handler) getNodeVersionToDelete(ctx context.Context, bkt *data.BucketInfo, obj *VersionedObject) (*data.NodeVersion, error) {
	objVersion := &ObjectVersion{
		BktInfo:               bkt,
		ObjectName:            obj.Name,
		VersionID:             obj.VersionID,
		NoErrorOnDeleteMarker: true,
	}

	return h.getNodeVersion(ctx, objVersion)
}

func (h *handler) removeOldVersion(ctx context.Context, bkt *data.BucketInfo, nodeVersion *data.NodeVersion, obj *VersionedObject) (string, error) {
	if nodeVersion.IsDeleteMarker() {
		return obj.VersionID, nil
	}

	return "", h.objectDelete(ctx, bkt, nodeVersion.OID)
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

func dismissNotFoundError(obj *VersionedObject) *VersionedObject {
	if s3errors.IsS3Error(obj.Error, s3errors.ErrNoSuchKey) ||
		s3errors.IsS3Error(obj.Error, s3errors.ErrNoSuchVersion) {
		obj.Error = nil
	}

	return obj
}

// IsAuthenticatedRequest checks if access box exists in the current request.
func IsAuthenticatedRequest(ctx context.Context) bool {
	_, ok := ctx.Value(api.BoxData).(*accessbox.Box)
	return ok
}

func IsSystemHeader(key string) bool {
	_, ok := api.SystemMetadata[key]
	return ok || strings.HasPrefix(key, api.NeoFSSystemMetadataPrefix)
}
func (h *handler) getObjectTaggingAndLock(ctx context.Context, objVersion *ObjectVersion, nodeVersion *data.NodeVersion) (map[string]string, *data.LockInfo, error) {
	var err error
	owner := h.Owner(ctx)

	tags := h.cache.GetTagging(owner, objectTaggingCacheKey(objVersion))
	lockInfo := h.cache.GetLockInfo(owner, lockObjectKey(objVersion))

	if tags != nil && lockInfo != nil {
		return tags, lockInfo, nil
	}

	if nodeVersion == nil {
		nodeVersion, err = h.getNodeVersion(ctx, objVersion)
		if err != nil {
			return nil, nil, err
		}
	}

	tags, lockInfo, err = h.treeService.GetObjectTaggingAndLock(ctx, objVersion.BktInfo, nodeVersion)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}
		return nil, nil, err
	}

	h.cache.PutTagging(owner, objectTaggingCacheKey(objVersion), tags)
	h.cache.PutLockInfo(owner, lockObjectKey(objVersion), lockInfo)

	return tags, lockInfo, nil
}

func (h *handler) containerList(ctx context.Context) ([]*data.BucketInfo, error) {
	var (
		err error
		own = h.Owner(ctx)
		res []cid.ID
		rid = api.GetRequestID(ctx)
	)
	res, err = h.neoFS.UserContainers(ctx, own)
	if err != nil {
		h.log.Error("could not list user containers",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]*data.BucketInfo, 0, len(res))
	for i := range res {
		info, err := h.containerInfo(ctx, res[i])
		if err != nil {
			h.log.Error("could not fetch container info",
				zap.String("request_id", rid),
				zap.Error(err))
			continue
		}

		list = append(list, info)
	}

	return list, nil
}

func (h *handler) createMultipartUpload(ctx context.Context, p *CreateMultipartParams) error {
	metaSize := len(p.Header)
	if p.Data != nil {
		metaSize += len(p.Data.ACLHeaders)
		metaSize += len(p.Data.TagSet)
	}

	info := &data.MultipartInfo{
		Key:          p.Info.Key,
		UploadID:     p.Info.UploadID,
		Owner:        h.Owner(ctx),
		Created:      TimeNow(ctx),
		Meta:         make(map[string]string, metaSize),
		CopiesNumber: p.CopiesNumber,
	}

	for key, val := range p.Header {
		info.Meta[metaPrefix+key] = val
	}

	if p.Data != nil {
		for key, val := range p.Data.ACLHeaders {
			info.Meta[aclPrefix+key] = val
		}

		for key, val := range p.Data.TagSet {
			info.Meta[tagPrefix+key] = val
		}
	}

	if p.Info.Encryption.Enabled() {
		if err := addEncryptionHeaders(info.Meta, p.Info.Encryption); err != nil {
			return fmt.Errorf("add encryption header: %w", err)
		}
	}

	return h.treeService.CreateMultipartUpload(ctx, p.Info.Bkt, info)
}

func (h *handler) UploadPart(ctx context.Context, p *UploadPartParams) (string, error) {
	multipartInfo, err := h.treeService.GetMultipartUpload(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return "", s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return "", err
	}

	if p.Size > uploadMaxSize {
		return "", s3errors.GetAPIError(s3errors.ErrEntityTooLarge)
	}

	objInfo, err := h.uploadPart(ctx, multipartInfo, p)
	if err != nil {
		return "", err
	}

	return objInfo.HashSum, nil
}

func (h *handler) uploadPart(ctx context.Context, multipartInfo *data.MultipartInfo, p *UploadPartParams) (*data.ObjectInfo, error) {
	encInfo := FormEncryptionInfo(multipartInfo.Meta)
	if err := p.Info.Encryption.MatchObjectEncryption(encInfo); err != nil {
		h.log.Warn("mismatched obj encryptionInfo", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionParameters)
	}

	bktInfo := p.Info.Bkt
	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Attributes:   make([][2]string, 2),
		Payload:      p.Reader,
		CreationTime: TimeNow(ctx),
		CopiesNumber: multipartInfo.CopiesNumber,
	}

	decSize := p.Size
	if p.Info.Encryption.Enabled() {
		r, encSize, err := encryptionReader(p.Reader, uint64(p.Size), p.Info.Encryption.Key())
		if err != nil {
			return nil, fmt.Errorf("failed to create ecnrypted reader: %w", err)
		}
		prm.Attributes = append(prm.Attributes, [2]string{AttributeDecryptedSize, strconv.FormatInt(p.Size, 10)})
		prm.Payload = r
		p.Size = int64(encSize)
	}

	prm.Attributes[0][0], prm.Attributes[0][1] = UploadIDAttributeName, p.Info.UploadID
	prm.Attributes[1][0], prm.Attributes[1][1] = UploadPartNumberAttributeName, strconv.Itoa(p.PartNumber)

	id, hash, err := h.objectPutAndHash(ctx, prm, bktInfo)
	if err != nil {
		return nil, err
	}

	partInfo := &data.PartInfo{
		Key:      p.Info.Key,
		UploadID: p.Info.UploadID,
		Number:   p.PartNumber,
		OID:      id,
		Size:     decSize,
		ETag:     hex.EncodeToString(hash),
		Created:  prm.CreationTime,
	}

	oldPartID, err := h.treeService.AddPart(ctx, bktInfo, multipartInfo.ID, partInfo)
	oldPartIDNotFound := errors.Is(err, ErrNoNodeToRemove)
	if err != nil && !oldPartIDNotFound {
		return nil, err
	}
	if !oldPartIDNotFound {
		if err = h.objectDelete(ctx, bktInfo, oldPartID); err != nil {
			h.log.Error("couldn't delete old part object", zap.Error(err),
				zap.String("cnrID", bktInfo.CID.EncodeToString()),
				zap.String("bucket name", bktInfo.Name),
				zap.String("objID", oldPartID.EncodeToString()))
		}
	}

	objInfo := &data.ObjectInfo{
		ID:  id,
		CID: bktInfo.CID,

		Owner:   bktInfo.Owner,
		Bucket:  bktInfo.Name,
		Size:    partInfo.Size,
		Created: partInfo.Created,
		HashSum: partInfo.ETag,
	}

	return objInfo, nil
}

func (h *handler) uploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error) {
	multipartInfo, err := h.treeService.GetMultipartUpload(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return nil, err
	}

	size := p.SrcObjInfo.Size
	if p.Range != nil {
		size = int64(p.Range.End - p.Range.Start + 1)
		if p.Range.End > uint64(p.SrcObjInfo.Size) {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidCopyPartRangeSource)
		}
	}
	if size > uploadMaxSize {
		return nil, s3errors.GetAPIError(s3errors.ErrEntityTooLarge)
	}

	pr, pw := io.Pipe()

	go func() {
		err = h.getObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObjInfo,
			Writer:     pw,
			Range:      p.Range,
			BucketInfo: p.SrcBktInfo,
		})

		if err = pw.CloseWithError(err); err != nil {
			h.log.Error("could not get object", zap.Error(err))
		}
	}()

	params := &UploadPartParams{
		Info:       p.Info,
		PartNumber: p.PartNumber,
		Size:       size,
		Reader:     pr,
	}

	return h.uploadPart(ctx, multipartInfo, params)
}

// implements io.Reader of payloads of the object list stored in the NeoFS network.
type multiObjectReader struct {
	ctx context.Context

	layer *handler

	prm getParams

	curReader io.Reader

	parts []*data.PartInfo
}

func (x *multiObjectReader) Read(p []byte) (n int, err error) {
	if x.curReader != nil {
		n, err = x.curReader.Read(p)
		if !errors.Is(err, io.EOF) {
			return n, err
		}
	}

	if len(x.parts) == 0 {
		return n, io.EOF
	}

	x.prm.oid = x.parts[0].OID

	x.curReader, err = x.layer.initObjectPayloadReader(x.ctx, x.prm)
	if err != nil {
		return n, fmt.Errorf("init payload reader for the next part: %w", err)
	}

	x.parts = x.parts[1:]

	next, err := x.Read(p[n:])

	return n + next, err
}

func (h *handler) completeMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*UploadData, *data.ExtendedObjectInfo, error) {
	for i := 1; i < len(p.Parts); i++ {
		if p.Parts[i].PartNumber <= p.Parts[i-1].PartNumber {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPartOrder)
		}
	}

	multipartInfo, partsInfo, err := h.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, nil, err
	}
	encInfo := FormEncryptionInfo(multipartInfo.Meta)

	if len(partsInfo) < len(p.Parts) {
		return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPart)
	}

	var multipartObjetSize int64
	var encMultipartObjectSize uint64
	parts := make([]*data.PartInfo, 0, len(p.Parts))

	var completedPartsHeader strings.Builder
	for i, part := range p.Parts {
		partInfo := partsInfo[part.PartNumber]
		if partInfo == nil || part.ETag != partInfo.ETag {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPart)
		}
		// for the last part we have no minimum size limit
		if i != len(p.Parts)-1 && partInfo.Size < uploadMinSize {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrEntityTooSmall)
		}
		parts = append(parts, partInfo)
		multipartObjetSize += partInfo.Size // even if encryption is enabled size is actual (decrypted)

		if encInfo.Enabled {
			encPartSize, err := sio.EncryptedSize(uint64(partInfo.Size))
			if err != nil {
				return nil, nil, fmt.Errorf("compute encrypted size: %w", err)
			}
			encMultipartObjectSize += encPartSize
		}

		partInfoStr := partInfo.ToHeaderString()
		if i != len(p.Parts)-1 {
			partInfoStr += ","
		}
		if _, err = completedPartsHeader.WriteString(partInfoStr); err != nil {
			return nil, nil, err
		}
	}

	initMetadata := make(map[string]string, len(multipartInfo.Meta)+1)
	initMetadata[UploadCompletedParts] = completedPartsHeader.String()

	uploadData := &UploadData{
		TagSet:     make(map[string]string),
		ACLHeaders: make(map[string]string),
	}
	for key, val := range multipartInfo.Meta {
		if strings.HasPrefix(key, metaPrefix) {
			initMetadata[strings.TrimPrefix(key, metaPrefix)] = val
		} else if strings.HasPrefix(key, tagPrefix) {
			uploadData.TagSet[strings.TrimPrefix(key, tagPrefix)] = val
		} else if strings.HasPrefix(key, aclPrefix) {
			uploadData.ACLHeaders[strings.TrimPrefix(key, aclPrefix)] = val
		}
	}

	if encInfo.Enabled {
		initMetadata[AttributeEncryptionAlgorithm] = encInfo.Algorithm
		initMetadata[AttributeHMACKey] = encInfo.HMACKey
		initMetadata[AttributeHMACSalt] = encInfo.HMACSalt
		initMetadata[AttributeDecryptedSize] = strconv.FormatInt(multipartObjetSize, 10)
		multipartObjetSize = int64(encMultipartObjectSize)
	}

	r := &multiObjectReader{
		ctx:   ctx,
		layer: h,
		parts: parts,
	}

	r.prm.bktInfo = p.Info.Bkt

	extObjInfo, err := h.putObject(ctx, &PutObjectParams{
		BktInfo:      p.Info.Bkt,
		Object:       p.Info.Key,
		Reader:       r,
		Header:       initMetadata,
		Size:         multipartObjetSize,
		Encryption:   p.Info.Encryption,
		CopiesNumber: multipartInfo.CopiesNumber,
	})
	if err != nil {
		h.log.Error("could not put a completed object (multipart upload)",
			zap.String("uploadID", p.Info.UploadID),
			zap.String("uploadKey", p.Info.Key),
			zap.Error(err))

		return nil, nil, s3errors.GetAPIError(s3errors.ErrInternalError)
	}

	var addr oid.Address
	addr.SetContainer(p.Info.Bkt.CID)
	for _, partInfo := range partsInfo {
		if err = h.objectDelete(ctx, p.Info.Bkt, partInfo.OID); err != nil {
			h.log.Warn("could not delete upload part",
				zap.Stringer("object id", &partInfo.OID),
				zap.Stringer("bucket id", p.Info.Bkt.CID),
				zap.Error(err))
		}
		addr.SetObject(partInfo.OID)
		h.cache.DeleteObject(addr)
	}

	return uploadData, extObjInfo, h.treeService.DeleteMultipartUpload(ctx, p.Info.Bkt, multipartInfo.ID)
}

func (h *handler) listMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error) {
	var result ListMultipartUploadsInfo
	if p.MaxUploads == 0 {
		return &result, nil
	}

	multipartInfos, err := h.treeService.GetMultipartUploadsByPrefix(ctx, p.Bkt, p.Prefix)
	if err != nil {
		return nil, err
	}

	uploads := make([]*UploadInfo, 0, len(multipartInfos))
	uniqDirs := make(map[string]struct{})

	for _, multipartInfo := range multipartInfos {
		info := uploadInfoFromMultipartInfo(multipartInfo, p.Prefix, p.Delimiter)
		if info != nil {
			if info.IsDir {
				if _, ok := uniqDirs[info.Key]; ok {
					continue
				}
				uniqDirs[info.Key] = struct{}{}
			}
			uploads = append(uploads, info)
		}
	}

	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key == uploads[j].Key {
			return uploads[i].UploadID < uploads[j].UploadID
		}
		return uploads[i].Key < uploads[j].Key
	})

	if p.KeyMarker != "" {
		if p.UploadIDMarker != "" {
			uploads = trimAfterUploadIDAndKey(p.KeyMarker, p.UploadIDMarker, uploads)
		} else {
			uploads = trimAfterUploadKey(p.KeyMarker, uploads)
		}
	}

	if len(uploads) > p.MaxUploads {
		result.IsTruncated = true
		uploads = uploads[:p.MaxUploads]
		result.NextUploadIDMarker = uploads[len(uploads)-1].UploadID
		result.NextKeyMarker = uploads[len(uploads)-1].Key
	}

	for _, ov := range uploads {
		if ov.IsDir {
			result.Prefixes = append(result.Prefixes, ov.Key)
		} else {
			result.Uploads = append(result.Uploads, ov)
		}
	}

	return &result, nil
}

func (h *handler) abortMultipartUpload(ctx context.Context, p *UploadInfoParams) error {
	multipartInfo, parts, err := h.getUploadParts(ctx, p)
	if err != nil {
		return err
	}

	for _, info := range parts {
		if err = h.objectDelete(ctx, p.Bkt, info.OID); err != nil {
			h.log.Warn("couldn't delete part", zap.String("cid", p.Bkt.CID.EncodeToString()),
				zap.String("oid", info.OID.EncodeToString()), zap.Int("part number", info.Number), zap.Error(err))
		}
	}

	return h.treeService.DeleteMultipartUpload(ctx, p.Bkt, multipartInfo.ID)
}

func (h *handler) listParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error) {
	var res ListPartsInfo
	multipartInfo, partsInfo, err := h.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, err
	}

	encInfo := FormEncryptionInfo(multipartInfo.Meta)
	if err = p.Info.Encryption.MatchObjectEncryption(encInfo); err != nil {
		h.log.Warn("mismatched obj encryptionInfo", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionParameters)
	}

	res.Owner = multipartInfo.Owner

	parts := make([]*Part, 0, len(partsInfo))

	for _, partInfo := range partsInfo {
		parts = append(parts, &Part{
			ETag:         partInfo.ETag,
			LastModified: partInfo.Created.UTC().Format(time.RFC3339),
			PartNumber:   partInfo.Number,
			Size:         partInfo.Size,
		})
	}

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	if p.PartNumberMarker != 0 {
		for i, part := range parts {
			if part.PartNumber > p.PartNumberMarker {
				parts = parts[i:]
				break
			}
		}
	}

	if len(parts) > p.MaxParts {
		res.IsTruncated = true
		res.NextPartNumberMarker = parts[p.MaxParts-1].PartNumber
		parts = parts[:p.MaxParts]
	}

	res.Parts = parts

	return &res, nil
}

func (h *handler) getUploadParts(ctx context.Context, p *UploadInfoParams) (*data.MultipartInfo, map[int]*data.PartInfo, error) {
	multipartInfo, err := h.treeService.GetMultipartUpload(ctx, p.Bkt, p.Key, p.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return nil, nil, err
	}

	parts, err := h.treeService.GetParts(ctx, p.Bkt, multipartInfo.ID)
	if err != nil {
		return nil, nil, err
	}

	res := make(map[int]*data.PartInfo, len(parts))
	for _, part := range parts {
		res[part.Number] = part
	}

	return multipartInfo, res, nil
}

func trimAfterUploadIDAndKey(key, id string, uploads []*UploadInfo) []*UploadInfo {
	var res []*UploadInfo
	if len(uploads) != 0 && uploads[len(uploads)-1].Key < key {
		return res
	}

	for _, obj := range uploads {
		if obj.Key >= key && obj.UploadID > id {
			res = append(res, obj)
		}
	}

	return res
}

func trimAfterUploadKey(key string, objects []*UploadInfo) []*UploadInfo {
	var result []*UploadInfo
	if len(objects) != 0 && objects[len(objects)-1].Key <= key {
		return result
	}
	for i, obj := range objects {
		if obj.Key > key {
			result = objects[i:]
			break
		}
	}

	return result
}

func uploadInfoFromMultipartInfo(uploadInfo *data.MultipartInfo, prefix, delimiter string) *UploadInfo {
	var isDir bool
	key := uploadInfo.Key

	if !strings.HasPrefix(key, prefix) {
		return nil
	}

	if len(delimiter) > 0 {
		tail := strings.TrimPrefix(key, prefix)
		index := strings.Index(tail, delimiter)
		if index >= 0 {
			isDir = true
			key = prefix + tail[:index+1]
		}
	}

	return &UploadInfo{
		IsDir:    isDir,
		Key:      key,
		UploadID: uploadInfo.UploadID,
		Owner:    uploadInfo.Owner,
		Created:  uploadInfo.Created,
	}
}

func (h *handler) putBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error {
	confXML, err := xml.Marshal(p.Configuration)
	if err != nil {
		return fmt.Errorf("marshal notify configuration: %w", err)
	}

	prm := PrmObjectCreate{
		Container:    p.BktInfo.CID,
		Creator:      p.BktInfo.Owner,
		Payload:      bytes.NewReader(confXML),
		Filepath:     p.BktInfo.NotificationConfigurationObjectName(),
		CreationTime: TimeNow(ctx),
		CopiesNumber: p.CopiesNumber,
	}

	objID, _, err := h.objectPutAndHash(ctx, prm, p.BktInfo)
	if err != nil {
		return err
	}

	objIDToDelete, err := h.treeService.PutNotificationConfigurationNode(ctx, p.BktInfo, objID)
	objIDToDeleteNotFound := errors.Is(err, ErrNoNodeToRemove)
	if err != nil && !objIDToDeleteNotFound {
		return err
	}

	if !objIDToDeleteNotFound {
		if err = h.objectDelete(ctx, p.BktInfo, objIDToDelete); err != nil {
			h.log.Error("couldn't delete notification configuration object", zap.Error(err),
				zap.String("cnrID", p.BktInfo.CID.EncodeToString()),
				zap.String("bucket name", p.BktInfo.Name),
				zap.String("objID", objIDToDelete.EncodeToString()))
		}
	}

	h.cache.PutNotificationConfiguration(h.Owner(ctx), p.BktInfo, p.Configuration)

	return nil
}

func (h *handler) getBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	owner := h.Owner(ctx)
	if conf := h.cache.GetNotificationConfiguration(owner, bktInfo); conf != nil {
		return conf, nil
	}

	objID, err := h.treeService.GetNotificationConfigurationNode(ctx, bktInfo)
	objIDNotFound := errors.Is(err, ErrNodeNotFound)
	if err != nil && !objIDNotFound {
		return nil, err
	}

	conf := &data.NotificationConfiguration{}

	if !objIDNotFound {
		obj, err := h.objectGet(ctx, bktInfo, objID)
		if err != nil {
			return nil, err
		}

		if err = xml.Unmarshal(obj.Payload(), &conf); err != nil {
			return nil, fmt.Errorf("unmarshal notify configuration: %w", err)
		}
	}

	h.cache.PutNotificationConfiguration(owner, bktInfo, conf)

	return conf, nil
}

// listObjectsV1 returns objects in a bucket for requests of Version 1.
func (h *handler) listObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error) {
	var result ListObjectsInfoV1

	prm := allObjectParams{
		Bucket:    p.BktInfo,
		Delimiter: p.Delimiter,
		Prefix:    p.Prefix,
		MaxKeys:   p.MaxKeys,
		Marker:    p.Marker,
	}

	objects, next, err := h.getLatestObjectsVersions(ctx, prm)
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

// listObjectsV2 returns objects in a bucket for requests of Version 2.
func (h *handler) listObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error) {
	var result ListObjectsInfoV2

	prm := allObjectParams{
		Bucket:            p.BktInfo,
		Delimiter:         p.Delimiter,
		Prefix:            p.Prefix,
		MaxKeys:           p.MaxKeys,
		Marker:            p.StartAfter,
		ContinuationToken: p.ContinuationToken,
	}

	objects, next, err := h.getLatestObjectsVersions(ctx, prm)
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

func (h *handler) getLatestObjectsVersions(ctx context.Context, p allObjectParams) (objects []*data.ObjectInfo, next *data.ObjectInfo, err error) {
	if p.MaxKeys == 0 {
		return nil, nil, nil
	}

	owner := h.Owner(ctx)
	cacheKey := cache.CreateObjectsListCacheKey(p.Bucket.CID, p.Prefix, true)
	nodeVersions := h.cache.GetList(owner, cacheKey)

	if nodeVersions == nil {
		nodeVersions, err = h.treeService.GetLatestVersionsByPrefix(ctx, p.Bucket, p.Prefix)
		if err != nil {
			return nil, nil, err
		}
		h.cache.PutList(owner, cacheKey, nodeVersions)
	}

	if len(nodeVersions) == 0 {
		return nil, nil, nil
	}

	sort.Slice(nodeVersions, func(i, j int) bool {
		return nodeVersions[i].FilePath < nodeVersions[j].FilePath
	})

	poolCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	objOutCh, err := h.initWorkerPool(poolCtx, 2, p, nodesGenerator(poolCtx, p, nodeVersions))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init worker pool: %w", err)
	}

	objects = make([]*data.ObjectInfo, 0, p.MaxKeys)

	for obj := range objOutCh {
		objects = append(objects, obj)
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	if len(objects) > p.MaxKeys {
		next = objects[p.MaxKeys]
		objects = objects[:p.MaxKeys]
	}

	return
}

func nodesGenerator(ctx context.Context, p allObjectParams, nodeVersions []*data.NodeVersion) <-chan *data.NodeVersion {
	nodeCh := make(chan *data.NodeVersion)
	existed := make(map[string]struct{}, len(nodeVersions)) // to squash the same directories

	go func() {
		var generated int
	LOOP:
		for _, node := range nodeVersions {
			if shouldSkip(node, p, existed) {
				continue
			}

			select {
			case <-ctx.Done():
				break LOOP
			case nodeCh <- node:
				generated++
				if generated == p.MaxKeys+1 { // we use maxKeys+1 to be able to know nextMarker/nextContinuationToken
					break LOOP
				}
			}
		}
		close(nodeCh)
	}()

	return nodeCh
}

func shouldSkip(node *data.NodeVersion, p allObjectParams, existed map[string]struct{}) bool {
	if node.IsDeleteMarker() {
		return true
	}

	filePath := node.FilePath
	if dirName := tryDirectoryName(node, p.Prefix, p.Delimiter); len(dirName) != 0 {
		filePath = dirName
	}
	if _, ok := existed[filePath]; ok {
		return true
	}

	if filePath <= p.Marker {
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

	existed[filePath] = struct{}{}
	return false
}

type logWrapper struct {
	log *zap.Logger
}

func (l *logWrapper) Printf(format string, args ...interface{}) {
	l.log.Info(fmt.Sprintf(format, args...))
}

func (h *handler) initWorkerPool(ctx context.Context, size int, p allObjectParams, input <-chan *data.NodeVersion) (<-chan *data.ObjectInfo, error) {
	pool, err := ants.NewPool(size, ants.WithLogger(&logWrapper{h.log}))
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
					oi := h.objectInfoFromObjectsCacheOrNeoFS(ctx, p.Bucket, node, p.Prefix, p.Delimiter)
					if oi == nil {
						// try to get object again
						if oi = h.objectInfoFromObjectsCacheOrNeoFS(ctx, p.Bucket, node, p.Prefix, p.Delimiter); oi == nil {
							// form object info with data that the tree node contains
							oi = getPartialObjectInfo(p.Bucket, node)
						}
					}
					select {
					case <-ctx.Done():
					case objCh <- oi:
					}
				})
				if err != nil {
					wg.Done()
					h.log.Warn("failed to submit task to pool", zap.Error(err))
				}
			}(node)
		}
		wg.Wait()
		close(objCh)
		pool.Release()
	}()

	return objCh, nil
}

// getPartialObjectInfo form data.ObjectInfo using data available in data.NodeVersion.
func getPartialObjectInfo(bktInfo *data.BucketInfo, node *data.NodeVersion) *data.ObjectInfo {
	return &data.ObjectInfo{
		ID:      node.OID,
		CID:     bktInfo.CID,
		Bucket:  bktInfo.Name,
		Name:    node.FilePath,
		Size:    node.Size,
		HashSum: node.ETag,
	}
}

func (h *handler) objectInfoFromObjectsCacheOrNeoFS(ctx context.Context, bktInfo *data.BucketInfo, node *data.NodeVersion, prefix, delimiter string) (oi *data.ObjectInfo) {
	if oiDir := tryDirectory(bktInfo, node, prefix, delimiter); oiDir != nil {
		return oiDir
	}

	owner := h.Owner(ctx)
	if extInfo := h.cache.GetObject(owner, newAddress(bktInfo.CID, node.OID)); extInfo != nil {
		return extInfo.ObjectInfo
	}

	meta, err := h.objectHead(ctx, bktInfo, node.OID)
	if err != nil {
		h.log.Warn("could not fetch object meta", zap.Error(err))
		return nil
	}

	oi = objectInfoFromMeta(bktInfo, meta)
	h.cache.PutObject(owner, &data.ExtendedObjectInfo{ObjectInfo: oi, NodeVersion: node})

	return oi
}

func (h *handler) listObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error) {
	var (
		allObjects = make([]*data.ExtendedObjectInfo, 0, p.MaxKeys)
		res        = &ListObjectVersionsInfo{}
	)

	versions, err := h.getAllObjectsVersions(ctx, p.BktInfo, p.Prefix, p.Delimiter)
	if err != nil {
		return nil, err
	}

	sortedNames := make([]string, 0, len(versions))
	for k := range versions {
		sortedNames = append(sortedNames, k)
	}
	sort.Strings(sortedNames)

	for _, name := range sortedNames {
		sortedVersions := versions[name]
		sort.Slice(sortedVersions, func(i, j int) bool {
			return sortedVersions[j].NodeVersion.Timestamp < sortedVersions[i].NodeVersion.Timestamp // sort in reverse order
		})

		for i, version := range sortedVersions {
			version.IsLatest = i == 0
			allObjects = append(allObjects, version)
		}
	}

	for i, obj := range allObjects {
		if obj.ObjectInfo.Name >= p.KeyMarker && obj.ObjectInfo.VersionID() >= p.VersionIDMarker {
			allObjects = allObjects[i:]
			break
		}
	}

	res.CommonPrefixes, allObjects = triageExtendedObjects(allObjects)

	if len(allObjects) > p.MaxKeys {
		res.IsTruncated = true
		res.NextKeyMarker = allObjects[p.MaxKeys].ObjectInfo.Name
		res.NextVersionIDMarker = allObjects[p.MaxKeys].ObjectInfo.VersionID()

		allObjects = allObjects[:p.MaxKeys]
		res.KeyMarker = allObjects[p.MaxKeys-1].ObjectInfo.Name
		res.VersionIDMarker = allObjects[p.MaxKeys-1].ObjectInfo.VersionID()
	}

	res.Version, res.DeleteMarker = triageVersions(allObjects)
	return res, nil
}

func triageVersions(objVersions []*data.ExtendedObjectInfo) ([]*data.ExtendedObjectInfo, []*data.ExtendedObjectInfo) {
	if len(objVersions) == 0 {
		return nil, nil
	}

	var resVersion []*data.ExtendedObjectInfo
	var resDelMarkVersions []*data.ExtendedObjectInfo

	for _, version := range objVersions {
		if version.NodeVersion.IsDeleteMarker() {
			resDelMarkVersions = append(resDelMarkVersions, version)
		} else {
			resVersion = append(resVersion, version)
		}
	}

	return resVersion, resDelMarkVersions
}

func (h *handler) getAllObjectsVersions(ctx context.Context, bkt *data.BucketInfo, prefix, delimiter string) (map[string][]*data.ExtendedObjectInfo, error) {
	nodeVersions, err := h.bucketNodeVersions(ctx, bkt, prefix)
	if err != nil {
		return nil, err
	}

	versions := make(map[string][]*data.ExtendedObjectInfo, len(nodeVersions))

	for _, nodeVersion := range nodeVersions {
		oi := &data.ObjectInfo{}

		if nodeVersion.IsDeleteMarker() { // delete marker does not match any object in NeoFS
			oi.ID = nodeVersion.OID
			oi.Name = nodeVersion.FilePath
			oi.Owner = nodeVersion.DeleteMarker.Owner
			oi.Created = nodeVersion.DeleteMarker.Created
			oi.IsDeleteMarker = true
		} else {
			if oi = h.objectInfoFromObjectsCacheOrNeoFS(ctx, bkt, nodeVersion, prefix, delimiter); oi == nil {
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

func (h *handler) createBucket(ctx context.Context, p *CreateBucketParams) (*data.BucketInfo, error) {
	bktInfo, err := h.getBucketInfo(ctx, p.Name)
	if err != nil {
		if s3errors.IsS3Error(err, s3errors.ErrNoSuchBucket) {
			return h.createContainer(ctx, p)
		}
		return nil, err
	}

	if p.SessionContainerCreation != nil && session.IssuedBy(*p.SessionContainerCreation, bktInfo.Owner) {
		return nil, s3errors.GetAPIError(s3errors.ErrBucketAlreadyOwnedByYou)
	}

	return nil, s3errors.GetAPIError(s3errors.ErrBucketAlreadyExists)
}

func (h *handler) createContainer(ctx context.Context, p *CreateBucketParams) (*data.BucketInfo, error) {
	ownerID := h.Owner(ctx)
	if p.LocationConstraint == "" {
		p.LocationConstraint = api.DefaultLocationConstraint // s3tests_boto3.functional.test_s3:test_bucket_get_location
	}
	bktInfo := &data.BucketInfo{
		Name:               p.Name,
		Owner:              ownerID,
		Created:            TimeNow(ctx),
		LocationConstraint: p.LocationConstraint,
		ObjectLockEnabled:  p.ObjectLockEnabled,
	}

	var attributes [][2]string

	attributes = append(attributes, [2]string{
		attributeLocationConstraint, p.LocationConstraint,
	})

	if p.ObjectLockEnabled {
		attributes = append(attributes, [2]string{
			AttributeLockEnabled, "true",
		})
	}

	idCnr, err := h.neoFS.CreateContainer(ctx, PrmContainerCreate{
		Creator:              bktInfo.Owner,
		Policy:               p.Policy,
		Name:                 p.Name,
		SessionToken:         p.SessionContainerCreation,
		CreationTime:         bktInfo.Created,
		AdditionalAttributes: attributes,
	})
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	bktInfo.CID = idCnr

	if err = h.setContainerEACLTable(ctx, bktInfo.CID, p.EACL, p.SessionEACL); err != nil {
		return nil, fmt.Errorf("set container eacl: %w", err)
	}

	h.cache.PutBucket(bktInfo)

	return bktInfo, nil
}
func (h *handler) setContainerEACLTable(ctx context.Context, idCnr cid.ID, table *eacl.Table, sessionToken *session.Container) error {
	table.SetCID(idCnr)

	return h.neoFS.SetContainerEACL(ctx, *table, sessionToken)
}
