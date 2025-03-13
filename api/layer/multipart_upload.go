package layer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sio"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"github.com/nspcc-dev/tzhash/tz"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	UploadCompletedParts = "S3-Completed-Parts"

	metaPrefix = "meta-"
	aclPrefix  = "acl-"

	MaxSizeUploadsList  = 1000
	MaxSizePartsList    = 1000
	UploadMinPartNumber = 1
	UploadMaxPartNumber = 10000
	uploadMinSize       = 5 * 1048576    // 5MB
	uploadMaxSize       = 5 * 1073741824 // 5GB
)

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
		ETag       string
		PartNumber int
		Size       int64
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

	uploadPartAsSlotParams struct {
		bktInfo          *data.BucketInfo
		multipartInfo    *data.MultipartInfo
		tzHash           hash.Hash
		attributes       map[string]string
		uploadPartParams *UploadPartParams
		creationTime     time.Time
		payloadReader    io.Reader
		decSize          int64
	}
)

func (n *layer) CreateMultipartUpload(ctx context.Context, p *CreateMultipartParams) (string, error) {
	metaSize := len(p.Header)
	if p.Data != nil {
		metaSize += len(p.Data.ACLHeaders)
		metaSize += len(p.Data.TagSet)
	}

	info := &data.MultipartInfo{
		Key:          p.Info.Key,
		Owner:        n.Owner(ctx),
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
			return "", fmt.Errorf("add encryption header: %w", err)
		}
	}

	zeroPartInfo, err := n.uploadZeroPart(ctx, info, p.Info)
	if err != nil {
		return "", fmt.Errorf("upload zero part: %w", err)
	}

	info.UploadID = zeroPartInfo.UploadID

	if err = n.createMultipartInfoObject(ctx, p.Info.Bkt, info); err != nil {
		return "", fmt.Errorf("create multipart upload: %w", err)
	}

	return zeroPartInfo.UploadID, nil
}

func (n *layer) UploadPart(ctx context.Context, p *UploadPartParams) (string, error) {
	multipartInfo, err := n.getMultipartInfoObject(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return "", s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return "", err
	}

	if p.Size > uploadMaxSize {
		return "", s3errors.GetAPIError(s3errors.ErrEntityTooLarge)
	}

	existingPart, err := n.multipartMetaGetPartByNumber(ctx, p.Info.Bkt, multipartInfo.UploadID, p.PartNumber)
	if err != nil {
		return "", fmt.Errorf("get existing part: %w", err)
	}

	if existingPart != nil {
		for _, item := range existingPart.Elements {
			if err = n.objectDelete(ctx, p.Info.Bkt, item.ID); err != nil {
				if !isErrObjectAlreadyRemoved(err) {
					return "", err
				}
			}
		}
	}

	objInfo, err := n.uploadPart(ctx, multipartInfo, p)
	if err != nil {
		return "", err
	}

	return objInfo.HashSum, nil
}

func (n *layer) uploadPart(ctx context.Context, multipartInfo *data.MultipartInfo, p *UploadPartParams) (*data.ObjectInfo, error) {
	encInfo := FormEncryptionInfo(multipartInfo.Meta)
	if err := p.Info.Encryption.MatchObjectEncryption(encInfo); err != nil {
		n.log.Warn("mismatched obj encryptionInfo", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionParameters)
	}

	var (
		bktInfo       = p.Info.Bkt
		payloadReader = p.Reader
		decSize       = p.Size
		attributes    = map[string]string{
			s3headers.MultipartObjectKey: multipartInfo.Key,
		}
	)

	if p.Info.Encryption.Enabled() {
		r, encSize, err := encryptionReader(p.Reader, uint64(p.Size), p.Info.Encryption.Key())
		if err != nil {
			return nil, fmt.Errorf("failed to create ecnrypted reader: %w", err)
		}
		attributes[AttributeDecryptedSize] = strconv.FormatInt(p.Size, 10)
		payloadReader = r
		p.Size = int64(encSize)
	}

	var (
		splitPreviousID oid.ID
		multipartHash   = sha256.New()
		tzHash          hash.Hash
		creationTime    = TimeNow(ctx)
	)

	if n.neoFS.IsHomomorphicHashingEnabled() {
		tzHash = tz.New()
	}

	lastPart, err := n.multipartMetaGetPartByNumber(ctx, bktInfo, multipartInfo.UploadID, p.PartNumber-1)
	if err != nil {
		return nil, fmt.Errorf("getLastPart: %w", err)
	}
	reqInfo := api.GetReqInfo(ctx)

	// The previous part is not uploaded yet.
	if lastPart == nil {
		params := uploadPartAsSlotParams{
			bktInfo:          bktInfo,
			multipartInfo:    multipartInfo,
			tzHash:           tzHash,
			attributes:       attributes,
			uploadPartParams: p,
			creationTime:     creationTime,
			payloadReader:    payloadReader,
			decSize:          decSize,
		}

		objInfo, err := n.uploadPartAsSlot(ctx, params)
		if err != nil {
			return nil, err
		}

		n.log.Debug("upload part as slot",
			zap.String("reqId", reqInfo.RequestID),
			zap.String("bucket", bktInfo.Name), zap.Stringer("cid", bktInfo.CID),
			zap.String("multipart upload", p.Info.UploadID),
			zap.Int("part number", p.PartNumber), zap.String("object", p.Info.Key), zap.Stringer("oid", objInfo.ID), zap.String("ETag", objInfo.HashSum), zap.Int64("decSize", decSize))

		return objInfo, nil
	}

	// try to restore hash state from the last part.
	// the required interface is guaranteed according to the docs, so just cast without checks.
	binaryUnmarshaler := multipartHash.(encoding.BinaryUnmarshaler)
	if err = binaryUnmarshaler.UnmarshalBinary(lastPart.MultipartHash); err != nil {
		return nil, fmt.Errorf("unmarshal previous part hash: %w", err)
	}

	if tzHash != nil {
		binaryUnmarshaler = tzHash.(encoding.BinaryUnmarshaler)
		if err = binaryUnmarshaler.UnmarshalBinary(lastPart.HomoHash); err != nil {
			return nil, fmt.Errorf("unmarshal previous part homo hash: %w", err)
		}
	}

	splitPreviousID = lastPart.OID

	splitFirstID, err := oid.DecodeString(multipartInfo.UploadID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multipart upload ID: %w", err)
	}

	var (
		id oid.ID
		// User may upload part large maxObjectSize in NeoFS. From users point of view it is a single object.
		// We have to calculate the hash from this object separately.
		currentPartHash = sha256.New()
	)

	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Attributes:   attributes,
		CreationTime: creationTime,
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			MultipartHashes: &MultipartHashes{
				Hash:     multipartHash,
				HomoHash: tzHash,
				PartHash: currentPartHash,
			},
		},
	}

	var (
		chunk          *[]byte
		isReturnToPool bool
	)

	if p.Size > n.neoFS.MaxObjectSize()/2 {
		chunk = n.buffers.Get().(*[]byte)
		isReturnToPool = true
	} else {
		smallChunk := make([]byte, p.Size)
		chunk = &smallChunk
	}

	if id, err = n.manualSlice(ctx, bktInfo, prm, p, splitFirstID, splitPreviousID, *chunk, payloadReader); err != nil {
		return nil, err
	}

	if isReturnToPool {
		n.buffers.Put(chunk)
	}

	partInfo := &data.PartInfo{
		UploadID: p.Info.UploadID,
		Number:   p.PartNumber,
		OID:      id,
		Size:     decSize,
		ETag:     hex.EncodeToString(currentPartHash.Sum(nil)),
		Created:  prm.CreationTime,
	}

	n.log.Debug(
		"upload part",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", bktInfo.Name),
		zap.Stringer("cid", bktInfo.CID),
		zap.String("multipart upload", p.Info.UploadID),
		zap.Int("part number", p.PartNumber),
		zap.String("object", p.Info.Key),
		zap.Stringer("oid", id),
		zap.String("ETag", partInfo.ETag),
		zap.Int64("decSize", decSize),
	)

	objInfo := &data.ObjectInfo{
		ID:  id,
		CID: bktInfo.CID,

		Owner:          bktInfo.Owner,
		OwnerPublicKey: bktInfo.OwnerPublicKey,
		Bucket:         bktInfo.Name,
		Size:           partInfo.Size,
		Created:        partInfo.Created,
		HashSum:        partInfo.ETag,
	}

	return objInfo, nil
}

func (n *layer) uploadZeroPart(ctx context.Context, multipartInfo *data.MultipartInfo, p *UploadInfoParams) (*data.PartInfo, error) {
	encInfo := FormEncryptionInfo(multipartInfo.Meta)
	if err := p.Encryption.MatchObjectEncryption(encInfo); err != nil {
		n.log.Warn("mismatched obj encryptionInfo", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionParameters)
	}

	var (
		bktInfo         = p.Bkt
		attributes      = make(map[string]string)
		multipartHash   = sha256.New()
		tzHash          hash.Hash
		id              oid.ID
		creationTime    = TimeNow(ctx)
		currentPartHash = sha256.New()
	)

	if p.Encryption.Enabled() {
		attributes[AttributeDecryptedSize] = "0"
	}

	if n.neoFS.IsHomomorphicHashingEnabled() {
		tzHash = tz.New()
	}

	attrs := make([]object.Attribute, 0, len(multipartInfo.Meta)+1)
	attrs = append(attrs, *object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(creationTime.Unix(), 10)))

	for key, val := range multipartInfo.Meta {
		if strings.HasPrefix(key, metaPrefix) {
			attrs = append(attrs, *object.NewAttribute(strings.TrimPrefix(key, metaPrefix), val))
		}
	}

	if encInfo.Enabled {
		attrs = append(attrs, *object.NewAttribute(AttributeEncryptionAlgorithm, encInfo.Algorithm))
		attrs = append(attrs, *object.NewAttribute(AttributeHMACKey, encInfo.HMACKey))
		attrs = append(attrs, *object.NewAttribute(AttributeHMACSalt, encInfo.HMACSalt))
	}

	var hashlessHeaderObject object.Object
	hashlessHeaderObject.SetContainerID(bktInfo.CID)
	hashlessHeaderObject.SetType(object.TypeRegular)
	hashlessHeaderObject.SetOwner(bktInfo.Owner)
	hashlessHeaderObject.SetAttributes(attrs...)
	hashlessHeaderObject.SetCreationEpoch(n.neoFS.CurrentEpoch())

	currentVersion := version.Current()
	hashlessHeaderObject.SetVersion(&currentVersion)

	// encoding hash.Hash state to save it in tree service.
	// the required interface is guaranteed according to the docs, so just cast without checks.
	binaryMarshaler := multipartHash.(encoding.BinaryMarshaler)
	stateBytes, err := binaryMarshaler.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalBinary: %w", err)
	}

	attributes[s3headers.MetaMultipartType] = s3headers.TypeMultipartPart
	attributes[s3headers.MultipartPartNumber] = "0"
	attributes[s3headers.MultipartElementID] = "0"
	attributes[s3headers.MultipartTotalSize] = "0"
	attributes[s3headers.MultipartHash] = hex.EncodeToString(stateBytes)
	attributes[s3headers.MultipartHomoHash] = ""

	if tzHash != nil {
		binaryMarshaler = tzHash.(encoding.BinaryMarshaler)
		stateBytes, err = binaryMarshaler.MarshalBinary()

		if err != nil {
			return nil, fmt.Errorf("marshalBinary: %w", err)
		}

		attributes[s3headers.MultipartHomoHash] = hex.EncodeToString(stateBytes)
	}

	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Attributes:   attributes,
		CreationTime: creationTime,
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			HeaderObject: &hashlessHeaderObject,
			PayloadHash:  sha256.New(),
		},
		Payload: bytes.NewBuffer(nil),
	}

	if n.neoFS.IsHomomorphicHashingEnabled() {
		prm.Multipart.HomoHash = tz.New()
	}

	id, err = n.multipartObjectPut(ctx, prm, bktInfo)
	if err != nil {
		return nil, err
	}

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("upload zero part",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", bktInfo.Name), zap.Stringer("cid", bktInfo.CID),
		zap.String("multipart upload", id.String()),
		zap.Int("part number", 0), zap.String("object", p.Key), zap.Stringer("oid", id))

	partInfo := &data.PartInfo{
		// UploadID equals zero part ID intentionally.
		UploadID: id.String(),
		Number:   0,
		OID:      id,
		Size:     0,
		ETag:     hex.EncodeToString(currentPartHash.Sum(nil)),
		Created:  prm.CreationTime,
	}

	return partInfo, nil
}

func (n *layer) multipartGetZeroPart(ctx context.Context, bktInfo *data.BucketInfo, uploadID string) (*data.PartInfo, error) {
	var zeroID oid.ID
	if err := zeroID.DecodeString(uploadID); err != nil {
		return nil, fmt.Errorf("unmarshal zero part id: %w", err)
	}

	obj, err := n.objectHead(ctx, bktInfo, zeroID)
	if err != nil {
		return nil, fmt.Errorf("head zero object: %w", err)
	}

	attrs := make(map[string]string, len(obj.Attributes()))
	for _, attr := range obj.Attributes() {
		attrs[attr.Key()] = attr.Value()
	}

	partInfo := data.PartInfo{
		OID: zeroID,
	}

	if partInfo.MultipartHash, err = hex.DecodeString(attrs[s3headers.MultipartHash]); err != nil {
		return nil, fmt.Errorf("convert multipart %s multipartHash %s: %w", uploadID, attrs[s3headers.MultipartHash], err)
	}

	if partInfo.HomoHash, err = hex.DecodeString(attrs[s3headers.MultipartHomoHash]); err != nil {
		return nil, fmt.Errorf("convert multipart %s homoHash %s: %w", uploadID, attrs[s3headers.MultipartHomoHash], err)
	}

	return &partInfo, nil
}

func (n *layer) multipartMetaGetPartByNumber(ctx context.Context, bktInfo *data.BucketInfo, uploadID string, number int) (*data.PartInfo, error) {
	if number < 0 {
		return nil, fmt.Errorf("part number can't be negative")
	}

	if number == 0 {
		return n.multipartGetZeroPart(ctx, bktInfo, uploadID)
	}

	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MultipartUpload,
			s3headers.MultipartHash,
			s3headers.MultipartHomoHash,
			s3headers.MultipartElementID,
		}
	)

	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MultipartPartNumber, strconv.Itoa(number), object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartPart, object.MatchStringEqual)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		return nil, fmt.Errorf("search objects: %w", err)
	}

	if len(res) == 0 {
		return nil, nil
	}

	elements := make([]data.ElementInfo, len(res))

	for i, item := range res {
		e := data.ElementInfo{
			ID: item.ID,
			Attributes: map[string]string{
				s3headers.MultipartHash:     item.Attributes[1],
				s3headers.MultipartHomoHash: item.Attributes[2],
			},
		}

		e.ElementID, err = strconv.Atoi(item.Attributes[3])
		if err != nil {
			return nil, fmt.Errorf("parse element id: %w", err)
		}

		elements[i] = e
	}

	slices.SortFunc(elements, func(a, b data.ElementInfo) int {
		return cmp.Compare(a.ElementID, b.ElementID)
	})

	var (
		lastElement             = elements[len(elements)-1]
		multipartHash, homoHash []byte
	)

	if multipartHash, err = hex.DecodeString(lastElement.Attributes[s3headers.MultipartHash]); err != nil {
		return nil, fmt.Errorf("convert %s:%s multipartHash %s: %w", uploadID, lastElement.ID.String(), lastElement.Attributes[s3headers.MultipartHash], err)
	}

	if homoHash, err = hex.DecodeString(lastElement.Attributes[s3headers.MultipartHomoHash]); err != nil {
		return nil, fmt.Errorf("convert %s:%s homoHash %s: %w", uploadID, lastElement.ID.String(), lastElement.Attributes[s3headers.MultipartHomoHash], err)
	}

	partInfo := data.PartInfo{
		OID:           lastElement.ID,
		MultipartHash: multipartHash,
		HomoHash:      homoHash,
		Elements:      elements,
	}

	return &partInfo, nil
}

func convertElementsToPartInfo(uploadID string, number int, elements []data.ElementInfo) (data.PartInfo, error) {
	slices.SortFunc(elements, func(a, b data.ElementInfo) int {
		return cmp.Compare(a.ElementID, b.ElementID)
	})

	var (
		err         error
		lastElement = elements[len(elements)-1]

		partInfo = data.PartInfo{
			UploadID: uploadID,
			Number:   number,
			OID:      lastElement.ID,
			Size:     lastElement.TotalSize,
			ETag:     lastElement.Attributes[s3headers.MultipartPartHash],
			Elements: elements,
		}
	)

	if partInfo.MultipartHash, err = hex.DecodeString(lastElement.Attributes[s3headers.MultipartHash]); err != nil {
		return data.PartInfo{}, fmt.Errorf("convert multipart %s multipartHash %s: %w", uploadID, lastElement.Attributes[s3headers.MultipartHash], err)
	}

	if partInfo.HomoHash, err = hex.DecodeString(lastElement.Attributes[s3headers.MultipartHomoHash]); err != nil {
		return data.PartInfo{}, fmt.Errorf("convert multipart %s multipartHomoHash %s: %w", uploadID, lastElement.Attributes[s3headers.MultipartHomoHash], err)
	}

	if v, ok := lastElement.Attributes[s3headers.MultipartIsArbitraryPart]; ok && v == "true" {
		partInfo.Elements = nil
	}

	return partInfo, nil
}

func (n *layer) createMultipartInfoObject(ctx context.Context, bktInfo *data.BucketInfo, info *data.MultipartInfo) error {
	var (
		attributes = make(map[string]string, 3)

		payloadMap = map[string]string{
			s3headers.MultipartObjectKey:    info.Key,
			s3headers.MultipartOwner:        info.Owner.EncodeToString(),
			s3headers.MultipartCreated:      strconv.FormatInt(info.Created.UTC().UnixMilli(), 10),
			s3headers.MultipartCopiesNumber: strconv.FormatUint(uint64(info.CopiesNumber), 10),
		}
	)

	if len(info.Meta) > 0 {
		objectAttributes, err := json.Marshal(info.Meta)
		if err != nil {
			return fmt.Errorf("meta marshaling: %w", err)
		}

		payloadMap[s3headers.MultipartMeta] = base64.StdEncoding.EncodeToString(objectAttributes)
	}

	payload, err := json.Marshal(payloadMap)
	if err != nil {
		return fmt.Errorf("meta marshaling: %w", err)
	}

	attributes[s3headers.MultipartUpload] = info.UploadID
	attributes[s3headers.MultipartObjectKey] = info.Key
	attributes[s3headers.MetaMultipartType] = s3headers.TypeMultipartInfo

	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Attributes:   attributes,
		CreationTime: info.Created.UTC(),
		CopiesNumber: info.CopiesNumber,
		Payload:      bytes.NewReader(payload),
		PayloadSize:  uint64(len(payload)),
	}

	_, _, err = n.objectPutAndHash(ctx, prm, bktInfo)
	if err != nil {
		return fmt.Errorf("create multipart info: %w", err)
	}

	return nil
}

func (n *layer) getMultipartInfoObject(ctx context.Context, bktInfo *data.BucketInfo, objectName, uploadID string) (*data.MultipartInfo, error) {
	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MultipartUpload,
			object.AttributeTimestamp,
		}
	)

	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MultipartObjectKey, objectName, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartInfo, object.MatchStringEqual)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	opts.SetCount(1)

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		return nil, fmt.Errorf("search objects: %w", err)
	}

	if len(res) == 0 {
		return nil, ErrNodeNotFound
	}

	slices.SortFunc(res, func(a, b client.SearchResultItem) int {
		// sort by object.AttributeTimestamp in reverse order
		return cmp.Compare(b.Attributes[1], a.Attributes[1])
	})

	obj, err := n.objectGet(ctx, bktInfo, res[0].ID)
	if err != nil {
		return nil, fmt.Errorf("get multipart %s object %s: %w", uploadID, res[0].ID.String(), err)
	}

	multipartInfo, err := n.parseMultipartInfoObject(uploadID, obj)
	if err != nil {
		return nil, fmt.Errorf("parse multipart %s object %s: %w", uploadID, res[0].ID.String(), err)
	}

	return &multipartInfo, nil
}

func (n *layer) getMultipartInfoByPrefix(ctx context.Context, bktInfo *data.BucketInfo, prefix, cursor string, maxKeys int) ([]data.MultipartInfo, string, error) {
	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MetaMultipartType,
			object.AttributeTimestamp,
			s3headers.MultipartUpload,
		}
	)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	if maxKeys <= 0 || maxKeys > 1000 {
		maxKeys = 1000
	}

	opts.SetCount(uint32(maxKeys))

	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartInfo, object.MatchStringEqual)
	filters.AddFilter(s3headers.MultipartObjectKey, prefix, object.MatchCommonPrefix)

	res, nextCursor, err := n.neoFS.SearchObjectsV2WithCursor(ctx, bktInfo.CID, filters, returningAttributes, cursor, opts)
	if err != nil {
		return nil, "", fmt.Errorf("search objects: %w", err)
	}

	if len(res) == 0 {
		return nil, "", nil
	}

	slices.SortFunc(res, func(a, b client.SearchResultItem) int {
		// sort by object.AttributeTimestamp in reverse order
		return cmp.Compare(b.Attributes[1], a.Attributes[1])
	})

	var (
		result = make([]data.MultipartInfo, len(res))
		obj    *object.Object
	)

	for i, item := range res {
		if obj, err = n.objectGet(ctx, bktInfo, item.ID); err != nil {
			return nil, "", fmt.Errorf("get multipart %s object %s: %w", item.Attributes[2], item.ID, err)
		}

		result[i], err = n.parseMultipartInfoObject(item.Attributes[2], obj)
		if err != nil {
			return nil, "", fmt.Errorf("parse multipart %s object %s: %w", item.Attributes[2], item.ID, err)
		}
	}

	return result, nextCursor, nil
}

func (n *layer) parseMultipartInfoObject(uploadID string, obj *object.Object) (data.MultipartInfo, error) {
	var (
		payloadMap map[string]string
	)

	var multipartInfo = data.MultipartInfo{
		ID:       obj.GetID(),
		UploadID: uploadID,
	}

	if err := json.Unmarshal(obj.Payload(), &payloadMap); err != nil {
		return data.MultipartInfo{}, fmt.Errorf("unmarshal multipart %s payload: %w", uploadID, err)
	}

	if err := multipartInfo.Owner.DecodeString(payloadMap[s3headers.MultipartOwner]); err != nil {
		return data.MultipartInfo{}, fmt.Errorf("unmarshal multipart %s owner %s : %w", uploadID, payloadMap[s3headers.MultipartOwner], err)
	}

	if utcMilli, err := strconv.ParseInt(payloadMap[s3headers.MultipartCreated], 10, 64); err == nil {
		multipartInfo.Created = time.UnixMilli(utcMilli)
	}

	if copies, err := strconv.ParseUint(payloadMap[s3headers.MultipartCopiesNumber], 10, 64); err == nil {
		if copies <= math.MaxUint32 {
			multipartInfo.CopiesNumber = uint32(copies)
		} else {
			return data.MultipartInfo{}, fmt.Errorf("copies number %d exceeds uint32 max value", copies)
		}
	}

	multipartInfo.Key = payloadMap[s3headers.MultipartObjectKey]

	if mpMeta, ok := payloadMap[s3headers.MultipartMeta]; ok {
		js, err := base64.StdEncoding.DecodeString(mpMeta)
		if err != nil {
			return data.MultipartInfo{}, fmt.Errorf("base64decode multipart meta %s : %w", uploadID, err)
		}

		if err = json.Unmarshal(js, &multipartInfo.Meta); err != nil {
			return data.MultipartInfo{}, fmt.Errorf("unmarshal multipart meta %s : %w", uploadID, err)
		}
	}

	return multipartInfo, nil
}

func (n *layer) DeleteMultipartUpload(ctx context.Context, bktInfo *data.BucketInfo, id oid.ID) error {
	return n.objectDelete(ctx, bktInfo, id)
}

func (n *layer) multipartMetaGetParts(ctx context.Context, bktInfo *data.BucketInfo, uploadID string) ([]*data.PartInfo, error) {
	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MultipartUpload,
			s3headers.MultipartPartNumber,
		}
	)

	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartPart, object.MatchStringEqual)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		return nil, fmt.Errorf("search objects: %w", err)
	}

	var zeroID oid.ID
	if err = zeroID.DecodeString(uploadID); err != nil {
		return nil, fmt.Errorf("unmarshal zero part id: %w", err)
	}

	res = append(res, client.SearchResultItem{ID: zeroID})

	var (
		obj    *object.Object
		number int

		partElementMap = make(map[int][]data.ElementInfo)
	)

	for _, item := range res {
		// requires 10 headers from object, thus we have to make heads.
		obj, err = n.objectHead(ctx, bktInfo, item.ID)
		if err != nil {
			return nil, fmt.Errorf("get multipart %s object: %w", uploadID, err)
		}

		element := data.ElementInfo{
			ID:         item.ID,
			Attributes: make(map[string]string, len(obj.Attributes())),
			Size:       int64(obj.PayloadSize()),
		}

		for _, attr := range obj.Attributes() {
			element.Attributes[attr.Key()] = attr.Value()
		}

		if number, err = strconv.Atoi(element.Attributes[s3headers.MultipartPartNumber]); err != nil {
			return nil, fmt.Errorf("convert multipart %s number %s: %w", uploadID, element.Attributes[s3headers.MultipartPartNumber], err)
		}

		if element.ElementID, err = strconv.Atoi(element.Attributes[s3headers.MultipartElementID]); err != nil {
			return nil, fmt.Errorf("convert multipart %s elementID %s: %w", uploadID, element.Attributes[s3headers.MultipartElementID], err)
		}

		if element.TotalSize, err = strconv.ParseInt(element.Attributes[s3headers.MultipartTotalSize], 10, 64); err != nil {
			return nil, fmt.Errorf("convert multipart %s MultipartTotalSize %s: %w", uploadID, element.Attributes[s3headers.MultipartTotalSize], err)
		}

		if decSize, ok := element.Attributes[AttributeDecryptedSize]; ok && decSize != "" {
			element.TotalSize, err = strconv.ParseInt(decSize, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("convert multipart %s AttributeDecryptedSize %s: %w", uploadID, element.Attributes[AttributeDecryptedSize], err)
			}
		}

		if _, ok := partElementMap[number]; !ok {
			partElementMap[number] = make([]data.ElementInfo, 0)
		}

		partElementMap[number] = append(partElementMap[number], element)
	}

	parts := make([]*data.PartInfo, 0, len(partElementMap))

	for partNumber, elements := range partElementMap {
		partInfo, err := convertElementsToPartInfo(uploadID, partNumber, elements)
		if err != nil {
			return nil, err
		}

		parts = append(parts, &partInfo)
	}

	slices.SortFunc(parts, data.SortPartInfo)

	return parts, nil
}

func (n *layer) multipartMetaGetOIDsForAbort(ctx context.Context, bktInfo *data.BucketInfo, uploadID string) ([]oid.ID, error) {
	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MultipartUpload,
		}
	)

	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartPart, object.MatchStringEqual)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		return nil, fmt.Errorf("search objects: %w", err)
	}

	var zeroID oid.ID
	if err = zeroID.DecodeString(uploadID); err != nil {
		return nil, fmt.Errorf("unmarshal zero part id: %w", err)
	}

	res = append(res, client.SearchResultItem{ID: zeroID})

	var (
		result = make([]oid.ID, len(res))
	)

	for i, item := range res {
		result[i] = item.ID
	}

	return result, nil
}

func (n *layer) multipartGetPartsList(ctx context.Context, bktInfo *data.BucketInfo, uploadID string) ([]*Part, error) {
	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MultipartUpload,
			s3headers.MultipartPartNumber,
			s3headers.MultipartPartHash,
			s3headers.MultipartElementID,
			s3headers.MultipartTotalSize,
			AttributeDecryptedSize,
		}
	)

	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartPart, object.MatchStringEqual)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		return nil, fmt.Errorf("search objects: %w", err)
	}

	if len(res) == 0 {
		return nil, nil
	}

	var (
		number         int
		partElementMap = make(map[int][]data.ElementInfo)
	)

	for _, item := range res {
		element := data.ElementInfo{
			ID:         item.ID,
			Attributes: make(map[string]string),
		}

		if number, err = strconv.Atoi(item.Attributes[1]); err != nil {
			return nil, fmt.Errorf("convert multipart %s number %s: %w", uploadID, item.Attributes[1], err)
		}

		element.Attributes[s3headers.MultipartPartHash] = item.Attributes[2]

		if element.ElementID, err = strconv.Atoi(item.Attributes[3]); err != nil {
			return nil, fmt.Errorf("convert multipart %s elementID %s: %w", uploadID, item.Attributes[3], err)
		}

		if element.TotalSize, err = strconv.ParseInt(item.Attributes[4], 10, 64); err != nil {
			return nil, fmt.Errorf("convert multipart %s totalSize %s: %w", uploadID, item.Attributes[4], err)
		}

		if decSize := item.Attributes[5]; decSize != "" {
			element.TotalSize, err = strconv.ParseInt(decSize, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("convert multipart %s decryptedSize %s: %w", uploadID, item.Attributes[5], err)
			}
		}

		if _, ok := partElementMap[number]; !ok {
			partElementMap[number] = make([]data.ElementInfo, 0)
		}

		partElementMap[number] = append(partElementMap[number], element)
	}

	parts := make([]*Part, 0, len(partElementMap))

	for partNumber, elements := range partElementMap {
		slices.SortFunc(elements, func(a, b data.ElementInfo) int {
			return cmp.Compare(a.ElementID, b.ElementID)
		})

		lastElement := elements[len(elements)-1]

		partInfo := Part{
			PartNumber: partNumber,
			Size:       lastElement.TotalSize,
			ETag:       lastElement.Attributes[s3headers.MultipartPartHash],
		}

		parts = append(parts, &partInfo)
	}

	return parts, nil
}

func (n *layer) multipartMetaGetPartsAfter(ctx context.Context, bktInfo *data.BucketInfo, uploadID string, partID int) ([]*data.PartInfo, error) {
	var (
		filters object.SearchFilters
		opts    client.SearchObjectsOptions

		returningAttributes = []string{
			s3headers.MultipartUpload,
		}
	)

	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartPart, object.MatchStringEqual)
	filters.AddFilter(s3headers.MultipartPartNumber, strconv.Itoa(partID), object.MatchNumGT)

	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		return nil, fmt.Errorf("search objects: %w", err)
	}

	if len(res) == 0 {
		return nil, nil
	}

	var (
		obj    *object.Object
		number int

		partElementMap = make(map[int][]data.ElementInfo)
	)

	for _, item := range res {
		obj, err = n.objectHead(ctx, bktInfo, item.ID)
		if err != nil {
			return nil, fmt.Errorf("get multipart %s object: %w", uploadID, err)
		}

		element := data.ElementInfo{
			ID:         item.ID,
			Attributes: make(map[string]string, len(obj.Attributes())),
			Size:       int64(obj.PayloadSize()),
		}

		for _, attr := range obj.Attributes() {
			element.Attributes[attr.Key()] = attr.Value()
		}

		if number, err = strconv.Atoi(element.Attributes[s3headers.MultipartPartNumber]); err != nil {
			return nil, fmt.Errorf("convert multipart %s number %s: %w", uploadID, element.Attributes[s3headers.MultipartPartNumber], err)
		}

		if element.ElementID, err = strconv.Atoi(element.Attributes[s3headers.MultipartElementID]); err != nil {
			return nil, fmt.Errorf("convert multipart %s elementID %s: %w", uploadID, element.Attributes[s3headers.MultipartElementID], err)
		}

		if element.TotalSize, err = strconv.ParseInt(element.Attributes[s3headers.MultipartTotalSize], 10, 64); err != nil {
			return nil, fmt.Errorf("convert multipart %s totalSize %s: %w", uploadID, element.Attributes[s3headers.MultipartTotalSize], err)
		}

		if _, ok := partElementMap[number]; !ok {
			partElementMap[number] = make([]data.ElementInfo, 0)
		}

		partElementMap[number] = append(partElementMap[number], element)
	}

	parts := make([]*data.PartInfo, 0, len(partElementMap))

	for partNumber, elements := range partElementMap {
		partInfo, err := convertElementsToPartInfo(uploadID, partNumber, elements)
		if err != nil {
			return nil, err
		}

		parts = append(parts, &partInfo)
	}

	slices.SortFunc(parts, data.SortPartInfo)

	return parts, nil
}

func (n *layer) reUploadFollowingParts(ctx context.Context, uploadParams UploadPartParams, partID int, bktInfo *data.BucketInfo, multipartInfo *data.MultipartInfo) error {
	parts, err := n.multipartMetaGetPartsAfter(ctx, bktInfo, multipartInfo.UploadID, partID)
	if err != nil {
		// nothing to re-upload.
		if errors.Is(err, ErrPartListIsEmpty) {
			return nil
		}

		return fmt.Errorf("get parts after: %w", err)
	}

	for _, part := range parts {
		uploadParams.PartNumber = part.Number

		if len(part.Elements) > 0 {
			if err = n.reUploadSegmentedPart(ctx, uploadParams, part, bktInfo, multipartInfo); err != nil {
				return fmt.Errorf("reupload number=%d: %w", part.Number, err)
			}
		} else {
			if err = n.reUploadPart(ctx, uploadParams, part.OID, bktInfo, multipartInfo); err != nil {
				return fmt.Errorf("reupload number=%d: %w", part.Number, err)
			}
		}
	}

	return nil
}

func (n *layer) reUploadSegmentedPart(ctx context.Context, uploadParams UploadPartParams, part *data.PartInfo, bktInfo *data.BucketInfo, multipartInfo *data.MultipartInfo) error {
	var (
		eg                     errgroup.Group
		pipeReader, pipeWriter = io.Pipe()
	)

	eg.Go(func() error {
		var (
			err        error
			elementObj *object.Object
		)

		for i, element := range part.Elements {
			n.log.Warn(
				"reUploadSegmentedPart elements",
				zap.Int("partNumber", part.Number),
				zap.Int("i", i),
				zap.String("oid", element.ID.String()),
				zap.Int("elementID", element.ElementID),
			)

			elementObj, err = n.objectGet(ctx, bktInfo, element.ID)
			if err != nil {
				err = fmt.Errorf("get part oid=%s, element oid=%s: %w", part.OID.String(), element.ID.String(), err)
				break
			}

			if _, err = pipeWriter.Write(elementObj.Payload()); err != nil {
				err = fmt.Errorf("write part oid=%s, element oid=%s: %w", part.OID.String(), element.ID.String(), err)
				break
			}

			if deleteErr := n.objectDelete(ctx, bktInfo, element.ID); deleteErr != nil {
				n.log.Error(
					"couldn't delete object",
					zap.Error(deleteErr),
					zap.String("cnrID", bktInfo.CID.EncodeToString()),
					zap.String("uploadID", multipartInfo.UploadID),
					zap.Int("partNumber", part.Number),
					zap.String("part.OID", part.OID.String()),
					zap.String("part element OID", element.ID.String()),
				)
				// no return intentionally.
			}
		}

		pipeCloseErr := pipeWriter.Close()

		if err != nil {
			return fmt.Errorf("pipe: %w", err)
		}

		if pipeCloseErr != nil {
			return fmt.Errorf("close writer part oid=%s: %w", part.OID.String(), err)
		}

		return nil
	})

	eg.Go(func() error {
		uploadParams.Size = part.Size
		uploadParams.Reader = pipeReader

		n.log.Debug("reUploadSegmentedPart", zap.String("oid", part.OID.String()), zap.Int64("payload size", uploadParams.Size), zap.Int("part", part.Number))
		if _, err := n.uploadPart(ctx, multipartInfo, &uploadParams); err != nil {
			return fmt.Errorf("upload id=%s: %w", part.OID.String(), err)
		}

		return nil
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("upload part oid=%s: %w", part.OID.String(), err)
	}

	return nil
}

func (n *layer) reUploadPart(ctx context.Context, uploadParams UploadPartParams, id oid.ID, bktInfo *data.BucketInfo, multipartInfo *data.MultipartInfo) error {
	obj, err := n.objectGet(ctx, bktInfo, id)
	if err != nil {
		return fmt.Errorf("get id=%s: %w", id.String(), err)
	}

	uploadParams.Size = int64(obj.PayloadSize())
	uploadParams.Reader = bytes.NewReader(obj.Payload())

	n.log.Debug("reUploadPart", zap.String("oid", id.String()), zap.Int("part", uploadParams.PartNumber), zap.Uint64("payload size", obj.PayloadSize()))
	if _, err = n.uploadPart(ctx, multipartInfo, &uploadParams); err != nil {
		return fmt.Errorf("upload id=%s: %w", id.String(), err)
	}

	// remove old object, we just re-uploaded a new one.
	if err = n.objectDelete(ctx, bktInfo, id); err != nil {
		if !isErrObjectAlreadyRemoved(err) {
			return fmt.Errorf("delete old id=%s: %w", id.String(), err)
		}
	}

	return nil
}

func (n *layer) UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error) {
	multipartInfo, err := n.getMultipartInfoObject(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
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
		err = n.GetObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObjInfo,
			Writer:     pw,
			Range:      p.Range,
			BucketInfo: p.SrcBktInfo,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	params := &UploadPartParams{
		Info:       p.Info,
		PartNumber: p.PartNumber,
		Size:       size,
		Reader:     pr,
	}

	objInfo, err := n.uploadPart(ctx, multipartInfo, params)
	if err != nil {
		return nil, fmt.Errorf("upload part: %w", err)
	}

	return objInfo, nil
}

func (n *layer) CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*UploadData, *data.ExtendedObjectInfo, error) {
	for i := 1; i < len(p.Parts); i++ {
		if p.Parts[i].PartNumber <= p.Parts[i-1].PartNumber {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPartOrder)
		}
	}

	partNumber, err := n.getFirstArbitraryPart(ctx, p.Info.UploadID, p.Info.Bkt)
	if err != nil {
		return nil, nil, fmt.Errorf("get first arbitrary part: %w", err)
	}

	// Take current multipart state.
	multipartInfo, err := n.getMultipartInfoObject(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}

		return nil, nil, fmt.Errorf("get multipart upload: %w", err)
	}

	// We need to fix Split.
	if partNumber > 0 {
		n.log.Debug("split fix required", zap.String("uploadID", p.Info.UploadID))

		var uploadPartParams = UploadPartParams{Info: p.Info}

		// We should take the part which broke the multipart upload sequence and re-upload all parts including this one.
		// This step rebuilds and recalculates Split chain and calculates the total object hash.
		if err = n.reUploadFollowingParts(ctx, uploadPartParams, int(partNumber-1), p.Info.Bkt, multipartInfo); err != nil {
			return nil, nil, fmt.Errorf("reupload following parts: %w", err)
		}
	}

	// Some actions above could change the multipart state, we need to take actual one.
	multipartInfo, partsInfo, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, nil, err
	}
	encInfo := FormEncryptionInfo(multipartInfo.Meta)

	if len(partsInfo) < len(p.Parts) {
		n.log.Debug(
			"parts amount mismatch",
			zap.Int("partsInfo", len(partsInfo)),
			zap.Int("p.Parts", len(p.Parts)),
		)
		return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPart)
	}

	var multipartObjetSize int64
	var encMultipartObjectSize uint64
	var lastPartID int
	var completedPartsHeader strings.Builder

	splitFirstID, err := oid.DecodeString(multipartInfo.UploadID)
	if err != nil {
		return nil, nil, fmt.Errorf("decode splitFirstID from UploadID :%w", err)
	}

	// +1 is the zero part, it equals to the uploadID.
	// +1 is the last part, it will be created later in the code.
	var measuredObjects = make([]object.MeasuredObject, 0, len(p.Parts)+2)

	// user know nothing about zero part, we have to add this part manually.
	var zeroObject object.MeasuredObject
	zeroObject.SetObjectID(splitFirstID)
	measuredObjects = append(measuredObjects, zeroObject)

	for i, part := range p.Parts {
		partInfo := partsInfo[part.PartNumber]
		if partInfo == nil || part.ETag != partInfo.ETag {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPart)
		}
		// for the last part we have no minimum size limit
		if i != len(p.Parts)-1 && partInfo.Size < uploadMinSize {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrEntityTooSmall)
		}
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

		if part.PartNumber > lastPartID {
			lastPartID = part.PartNumber
		}

		for _, element := range partInfo.Elements {
			// Collecting payload for the link object.
			var mObj object.MeasuredObject
			mObj.SetObjectID(element.ID)
			mObj.SetObjectSize(uint32(element.Size))
			measuredObjects = append(measuredObjects, mObj)
		}
	}

	multipartHash := sha256.New()
	var homoHash hash.Hash
	var splitPreviousID oid.ID

	if lastPartID > 0 {
		lastPart := partsInfo[lastPartID]

		if lastPart != nil {
			if len(lastPart.MultipartHash) > 0 {
				splitPreviousID = lastPart.OID

				if len(lastPart.MultipartHash) > 0 {
					binaryUnmarshaler := multipartHash.(encoding.BinaryUnmarshaler)
					if err = binaryUnmarshaler.UnmarshalBinary(lastPart.MultipartHash); err != nil {
						return nil, nil, fmt.Errorf("unmarshal last part hash: %w", err)
					}
				}
			}

			if n.neoFS.IsHomomorphicHashingEnabled() && len(lastPart.HomoHash) > 0 {
				homoHash = tz.New()

				if len(lastPart.HomoHash) > 0 {
					binaryUnmarshaler := homoHash.(encoding.BinaryUnmarshaler)
					if err = binaryUnmarshaler.UnmarshalBinary(lastPart.HomoHash); err != nil {
						return nil, nil, fmt.Errorf("unmarshal last part homo hash: %w", err)
					}
				}
			}
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
		n.log.Debug("big object", zap.Int64("size", multipartObjetSize), zap.Uint64("enc_size", encMultipartObjectSize))

		multipartObjetSize = int64(encMultipartObjectSize)
	}

	// This is our "big object". It doesn't have any payload.
	prmHeaderObject := &PutObjectParams{
		BktInfo:      p.Info.Bkt,
		Object:       p.Info.Key,
		Reader:       bytes.NewBuffer(nil),
		Header:       initMetadata,
		Size:         multipartObjetSize,
		Encryption:   p.Info.Encryption,
		CopiesNumber: multipartInfo.CopiesNumber,
	}

	bktSettings, err := n.GetBucketSettings(ctx, p.Info.Bkt)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't get versioning settings object: %w", err)
	}

	header, err := n.prepareMultipartHeadObject(ctx, prmHeaderObject, multipartHash, homoHash, uint64(multipartObjetSize), bktSettings.VersioningEnabled())
	if err != nil {
		return nil, nil, err
	}

	// last part
	prm := PrmObjectCreate{
		Container:    p.Info.Bkt.CID,
		Creator:      p.Info.Bkt.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			SplitFirstID:    &splitFirstID,
			SplitPreviousID: &splitPreviousID,
			HeaderObject:    header,
			PayloadHash:     sha256.New(),
		},
		Payload: bytes.NewBuffer(nil),
	}

	if n.neoFS.IsHomomorphicHashingEnabled() {
		prm.Multipart.HomoHash = tz.New()
	}

	lastPartObjID, err := n.multipartObjectPut(ctx, prm, p.Info.Bkt)
	if err != nil {
		return nil, nil, err
	}

	var mObj object.MeasuredObject
	// last part has the zero length.
	mObj.SetObjectID(lastPartObjID)
	measuredObjects = append(measuredObjects, mObj)

	var linkObj = object.Link{}
	linkObj.SetObjects(measuredObjects)

	// linking object
	prm = PrmObjectCreate{
		Container:    p.Info.Bkt.CID,
		Creator:      p.Info.Bkt.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			HeaderObject: header,
			SplitFirstID: &splitFirstID,
			Link:         &linkObj,
		},
	}

	_, err = n.multipartObjectPut(ctx, prm, p.Info.Bkt)
	if err != nil {
		return nil, nil, err
	}

	headerObjectID := header.GetID()

	// the "big object" is not presented in system, but we have to put correct info about it and its version.

	newVersion := &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			FilePath: p.Info.Key,
			OID:      headerObjectID,
			ETag:     hex.EncodeToString(multipartHash.Sum(nil)),
		},
		IsUnversioned: !bktSettings.VersioningEnabled(),
	}

	n.cache.CleanListCacheEntriesContainingObject(p.Info.Key, p.Info.Bkt.CID)

	objInfo := &data.ObjectInfo{
		ID:             headerObjectID,
		CID:            p.Info.Bkt.CID,
		Owner:          p.Info.Bkt.Owner,
		OwnerPublicKey: p.Info.Bkt.OwnerPublicKey,
		Bucket:         p.Info.Bkt.Name,
		Name:           p.Info.Key,
		Size:           multipartObjetSize,
		Created:        prm.CreationTime,
		Headers:        initMetadata,
		ContentType:    initMetadata[api.ContentType],
		HashSum:        newVersion.ETag,
	}

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: newVersion,
	}

	n.cache.PutObjectWithName(p.Info.Bkt.Owner, extObjInfo)

	return uploadData, extObjInfo, n.DeleteMultipartUpload(ctx, p.Info.Bkt, multipartInfo.ID)
}

func (n *layer) ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error) {
	var result ListMultipartUploadsInfo
	if p.MaxUploads == 0 {
		return &result, nil
	}

	if p.UploadIDMarker == "" && p.KeyMarker != "" {
		p.UploadIDMarker = generateContinuationToken(p.KeyMarker)
	}

	multipartInfos, nextCursor, err := n.getMultipartInfoByPrefix(ctx, p.Bkt, p.Prefix, p.UploadIDMarker, p.MaxUploads)
	if err != nil {
		return nil, err
	}

	if len(multipartInfos) == 0 {
		return &result, nil
	}

	uploads := make([]*UploadInfo, 0, len(multipartInfos))
	uniqDirs := make(map[string]struct{})

	for _, multipartInfo := range multipartInfos {
		info := uploadInfoFromMultipartInfo(&multipartInfo, p.Prefix, p.Delimiter)
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

	slices.SortFunc(uploads, func(a, b *UploadInfo) int {
		if compare := cmp.Compare(a.Key, b.Key); compare != 0 {
			return compare
		}
		return cmp.Compare(a.UploadID, b.UploadID)
	})

	if p.KeyMarker != "" {
		if p.UploadIDMarker != "" {
			uploads = trimAfterUploadIDAndKey(p.KeyMarker, p.UploadIDMarker, uploads)
		} else {
			uploads = trimAfterUploadKey(p.KeyMarker, uploads)
		}
	}

	result.IsTruncated = nextCursor != ""
	result.NextUploadIDMarker = nextCursor

	for _, ov := range uploads {
		if ov.IsDir {
			result.Prefixes = append(result.Prefixes, ov.Key)
		} else {
			result.Uploads = append(result.Uploads, ov)
		}
	}

	return &result, nil
}

func (n *layer) AbortMultipartUpload(ctx context.Context, p *UploadInfoParams) error {
	multipartInfo, err := n.getMultipartInfoObject(ctx, p.Bkt, p.Key, p.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return err
	}

	parts, err := n.multipartMetaGetOIDsForAbort(ctx, p.Bkt, p.UploadID)
	if err != nil {
		return nil
	}

	for _, id := range parts {
		if err = n.objectDelete(ctx, p.Bkt, id); err != nil {
			n.log.Warn("couldn't delete part element", zap.String("cid", p.Bkt.CID.EncodeToString()),
				zap.String("oid", id.String()), zap.Error(err), zap.String("uploadID", p.UploadID))
		}
	}

	return n.DeleteMultipartUpload(ctx, p.Bkt, multipartInfo.ID)
}

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error) {
	var res ListPartsInfo
	multipartInfo, err := n.getMultipartInfoObject(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return nil, err
	}

	encInfo := FormEncryptionInfo(multipartInfo.Meta)
	if err = p.Info.Encryption.MatchObjectEncryption(encInfo); err != nil {
		n.log.Warn("mismatched obj encryptionInfo", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionParameters)
	}

	res.Owner = multipartInfo.Owner

	parts, err := n.multipartGetPartsList(ctx, p.Info.Bkt, p.Info.UploadID)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(parts, func(a, b *Part) int {
		return cmp.Compare(a.PartNumber, b.PartNumber)
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

func (n *layer) getUploadParts(ctx context.Context, p *UploadInfoParams) (*data.MultipartInfo, map[int]*data.PartInfo, error) {
	multipartInfo, err := n.getMultipartInfoObject(ctx, p.Bkt, p.Key, p.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return nil, nil, err
	}

	parts, err := n.multipartMetaGetParts(ctx, p.Bkt, multipartInfo.UploadID)
	if err != nil {
		return nil, nil, err
	}

	// Sort parts by part number, then by server creation time to make actual last uploaded parts with the same number.
	slices.SortFunc(parts, data.SortPartInfo)

	res := make(map[int]*data.PartInfo, len(parts))
	partsNumbers := make([]int, len(parts))
	oids := make([]string, len(parts))
	for i, part := range parts {
		res[part.Number] = part
		partsNumbers[i] = part.Number
		oids[i] = part.OID.EncodeToString()
	}

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("part details",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", p.Bkt.Name),
		zap.Stringer("cid", p.Bkt.CID),
		zap.String("object", p.Key),
		zap.String("upload id", p.UploadID),
		zap.Ints("part numbers", partsNumbers),
		zap.Strings("oids", oids))

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

func (n *layer) manualSlice(ctx context.Context, bktInfo *data.BucketInfo, prm PrmObjectCreate, p *UploadPartParams, splitFirstID, splitPreviousID oid.ID, chunk []byte, payloadReader io.Reader) (oid.ID, error) {
	var (
		totalBytes int
		id         oid.ID
		err        error
		elementID  int
		stateBytes []byte
	)

	prm.Attributes[s3headers.MetaMultipartType] = s3headers.TypeMultipartPart
	prm.Attributes[s3headers.MultipartUpload] = p.Info.UploadID
	prm.Attributes[s3headers.MultipartPartNumber] = strconv.Itoa(p.PartNumber)

	// slice part manually. Simultaneously considering the part is a single object for user.
	for {
		elementID++
		prm.Attributes[s3headers.MultipartElementID] = strconv.Itoa(elementID)

		prm.Multipart.SplitPreviousID = &splitPreviousID

		if !splitFirstID.IsZero() {
			prm.Multipart.SplitFirstID = &splitFirstID
		}

		nBts, readErr := io.ReadAtLeast(payloadReader, chunk, len(chunk))
		totalBytes += nBts

		if nBts > 0 {
			prm.Payload = bytes.NewReader((chunk)[:nBts])
			prm.PayloadSize = uint64(nBts)
			prm.Multipart.PayloadHash = sha256.New()
			prm.Multipart.PayloadHash.Write((chunk)[:nBts])

			if n.neoFS.IsHomomorphicHashingEnabled() {
				prm.Multipart.HomoHash = tz.New()
				prm.Multipart.HomoHash.Write((chunk)[:nBts])
			}

			if err = prm.Multipart.MultipartHashes.WritePayload((chunk)[:nBts]); err != nil {
				return id, fmt.Errorf("hash payload write: %w", err)
			}

			binaryMarshaler := prm.Multipart.MultipartHashes.Hash.(encoding.BinaryMarshaler)
			stateBytes, err = binaryMarshaler.MarshalBinary()
			if err != nil {
				return id, fmt.Errorf("marshalBinary: %w", err)
			}
			prm.Attributes[s3headers.MultipartHash] = hex.EncodeToString(stateBytes)
			prm.Attributes[s3headers.MultipartHomoHash] = ""
			prm.Attributes[s3headers.MultipartTotalSize] = strconv.Itoa(totalBytes)
			prm.Attributes[s3headers.MultipartPartHash] = hex.EncodeToString(prm.Multipart.MultipartHashes.PartHash.Sum(nil))

			if prm.Multipart.MultipartHashes.HomoHash != nil {
				binaryMarshaler = prm.Multipart.MultipartHashes.HomoHash.(encoding.BinaryMarshaler)
				stateBytes, err = binaryMarshaler.MarshalBinary()

				if err != nil {
					return id, fmt.Errorf("marshalBinary: %w", err)
				}

				prm.Attributes[s3headers.MultipartHomoHash] = hex.EncodeToString(stateBytes)
			}

			id, err = n.multipartObjectPut(ctx, prm, bktInfo)
			if err != nil {
				return id, fmt.Errorf("multipart object put: %w", err)
			}

			n.log.Debug(
				"uploaded element",
				zap.String("upload", p.Info.UploadID),
				zap.Int("part", p.PartNumber),
				zap.Int("elementID", elementID),
				zap.String("oid", id.String()),
				zap.Int("size", nBts),
				zap.Int("totalSize", totalBytes),
			)

			splitPreviousID = id
		}

		if readErr == nil {
			continue
		}

		// If an EOF happens after reading fewer than min bytes, ReadAtLeast returns ErrUnexpectedEOF.
		// We have the whole payload.
		if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return id, fmt.Errorf("read payload chunk: %w", err)
		}

		break
	}

	return id, nil
}

// uploadPartAsSlot uploads multipart part, but without correct link to previous part because we don't have it.
// It uses zero part as pivot. Actual link will be set on CompleteMultipart.
func (n *layer) uploadPartAsSlot(ctx context.Context, params uploadPartAsSlotParams) (*data.ObjectInfo, error) {
	var (
		id                         oid.ID
		multipartHash              = sha256.New()
		mpHashBytes, homoHashBytes []byte
	)

	// encoding hash.Hash state to save it in tree service.
	// the required interface is guaranteed according to the docs, so just cast without checks.
	binaryMarshaler := multipartHash.(encoding.BinaryMarshaler)
	mpHashBytes, err := binaryMarshaler.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalBinary: %w", err)
	}

	params.attributes[s3headers.MultipartHash] = hex.EncodeToString(mpHashBytes)
	params.attributes[s3headers.MultipartHomoHash] = ""

	if params.tzHash != nil {
		binaryMarshaler = params.tzHash.(encoding.BinaryMarshaler)
		homoHashBytes, err = binaryMarshaler.MarshalBinary()

		if err != nil {
			return nil, fmt.Errorf("marshalBinary: %w", err)
		}

		params.attributes[s3headers.MultipartHomoHash] = hex.EncodeToString(homoHashBytes)
	}

	params.attributes[s3headers.MultipartUpload] = params.multipartInfo.UploadID
	params.attributes[s3headers.MultipartPartNumber] = strconv.FormatInt(int64(params.uploadPartParams.PartNumber), 10)
	params.attributes[s3headers.MetaMultipartType] = s3headers.TypeMultipartPart
	params.attributes[s3headers.MultipartIsArbitraryPart] = "true"
	params.attributes[s3headers.MultipartElementID] = "0"
	params.attributes[s3headers.MultipartTotalSize] = strconv.FormatInt(params.decSize, 10)

	prm := PrmObjectCreate{
		Container:    params.bktInfo.CID,
		Creator:      params.bktInfo.Owner,
		Attributes:   params.attributes,
		CreationTime: params.creationTime,
		CopiesNumber: params.multipartInfo.CopiesNumber,
		Payload:      params.payloadReader,
		PayloadSize:  uint64(params.decSize),
	}

	id, objHashBts, err := n.objectPutAndHash(ctx, prm, params.bktInfo)
	if err != nil {
		return nil, fmt.Errorf("object put and hash: %w", err)
	}

	partInfo := &data.PartInfo{
		UploadID: params.uploadPartParams.Info.UploadID,
		Number:   params.uploadPartParams.PartNumber,
		OID:      id,
		Size:     params.decSize,
		ETag:     hex.EncodeToString(objHashBts),
		Created:  prm.CreationTime,
	}

	objInfo := data.ObjectInfo{
		ID:  id,
		CID: params.bktInfo.CID,

		Owner:          params.bktInfo.Owner,
		OwnerPublicKey: params.bktInfo.OwnerPublicKey,
		Bucket:         params.bktInfo.Name,
		Size:           params.decSize,
		Created:        prm.CreationTime,
		HashSum:        partInfo.ETag,
	}

	return &objInfo, nil
}

func (n *layer) getFirstArbitraryPart(ctx context.Context, uploadID string, bucketInfo *data.BucketInfo) (int64, error) {
	var filters object.SearchFilters
	filters.AddFilter(s3headers.MultipartUpload, uploadID, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaMultipartType, s3headers.TypeMultipartPart, object.MatchStringEqual)
	filters.AddFilter(s3headers.MultipartIsArbitraryPart, "true", object.MatchStringEqual)

	var opts client.SearchObjectsOptions
	if bt := bearerTokenFromContext(ctx, bucketInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bucketInfo.CID, filters, []string{
		s3headers.MultipartUpload,
		s3headers.MultipartPartNumber,
	}, opts)
	if err != nil {
		return 0, fmt.Errorf("search objects: %w", err)
	}

	if len(res) == 0 {
		return 0, nil
	}

	slices.SortFunc(res, func(a, b client.SearchResultItem) int {
		return cmp.Compare(a.Attributes[1], b.Attributes[1])
	})

	partNumber, err := strconv.ParseInt(res[0].Attributes[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse header: %w", err)
	}

	return partNumber, nil
}
