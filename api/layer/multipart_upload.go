package layer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sio"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
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

	headerS3MultipartUpload  = "S3MultipartUpload"
	headerS3MultipartNumber  = "S3MultipartNumber"
	headerS3MultipartCreated = "S3MultipartCreated"
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
		OwnerPubKey          keys.PublicKey
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
		IsDir       bool
		Key         string
		UploadID    string
		Owner       user.ID
		OwnerPubKey keys.PublicKey
		Created     time.Time
	}

	slotAttributes struct {
		PartNumber int64
		// in nanoseconds
		CreatedAt int64
		FilePath  string
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

	ownerPubKey, err := n.OwnerPublicKey(ctx)
	if err != nil {
		return "", fmt.Errorf("owner pub key: %w", err)
	}

	info := &data.MultipartInfo{
		Key:          p.Info.Key,
		Owner:        n.Owner(ctx),
		OwnerPubKey:  *ownerPubKey,
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

	nodeID, err := n.treeService.CreateMultipartUpload(ctx, p.Info.Bkt, info)
	if err != nil {
		return "", fmt.Errorf("create multipart upload: %w", err)
	}

	if err = n.finalizeZeroPart(ctx, p.Info.Bkt, nodeID, zeroPartInfo); err != nil {
		return "", fmt.Errorf("finalize zero part: %w", err)
	}

	return zeroPartInfo.UploadID, nil
}

func (n *layer) UploadPart(ctx context.Context, p *UploadPartParams) (string, error) {
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return "", s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return "", err
	}

	if p.Size > uploadMaxSize {
		return "", s3errors.GetAPIError(s3errors.ErrEntityTooLarge)
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
		attributes    = make(map[string]string)
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
		splitFirstID    oid.ID
		multipartHash   = sha256.New()
		tzHash          hash.Hash
		creationTime    = TimeNow(ctx)
	)

	if n.neoFS.IsHomomorphicHashingEnabled() {
		tzHash = tz.New()
	}

	lastPart, err := n.treeService.GetPartByNumber(ctx, bktInfo, multipartInfo.ID, p.PartNumber-1)
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

	if err = splitFirstID.DecodeString(multipartInfo.UploadID); err != nil {
		return nil, fmt.Errorf("failed to decode multipart upload ID: %w", err)
	}

	var (
		id       oid.ID
		elements []data.LinkObjectPayload
		// User may upload part large maxObjectSize in NeoFS. From users point of view it is a single object.
		// We have to calculate the hash from this object separately.
		currentPartHash = sha256.New()
	)

	objHashes := []hash.Hash{multipartHash, currentPartHash}
	if tzHash != nil {
		objHashes = append(objHashes, tzHash)
	}

	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Attributes:   attributes,
		CreationTime: creationTime,
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			MultipartHashes: objHashes,
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

	if id, elements, err = n.manualSlice(ctx, bktInfo, prm, splitFirstID, splitPreviousID, *chunk, payloadReader); err != nil {
		return nil, err
	}

	if isReturnToPool {
		n.buffers.Put(chunk)
	}

	partInfo := &data.PartInfo{
		Key:      p.Info.Key,
		UploadID: p.Info.UploadID,
		Number:   p.PartNumber,
		OID:      id,
		Size:     decSize,
		ETag:     hex.EncodeToString(currentPartHash.Sum(nil)),
		Created:  prm.CreationTime,
		Elements: elements,
	}

	n.log.Debug("upload part",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", bktInfo.Name), zap.Stringer("cid", bktInfo.CID),
		zap.String("multipart upload", p.Info.UploadID),
		zap.Int("part number", p.PartNumber), zap.String("object", p.Info.Key), zap.Stringer("oid", id), zap.String("ETag", partInfo.ETag), zap.Int64("decSize", decSize))

	// encoding hash.Hash state to save it in tree service.
	// the required interface is guaranteed according to the docs, so just cast without checks.
	binaryMarshaler := multipartHash.(encoding.BinaryMarshaler)
	partInfo.MultipartHash, err = binaryMarshaler.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalBinary: %w", err)
	}

	if tzHash != nil {
		binaryMarshaler = tzHash.(encoding.BinaryMarshaler)
		partInfo.HomoHash, err = binaryMarshaler.MarshalBinary()

		if err != nil {
			return nil, fmt.Errorf("marshalBinary: %w", err)
		}
	}

	oldPartID, err := n.treeService.AddPart(ctx, bktInfo, multipartInfo.ID, partInfo)
	oldPartIDNotFound := errors.Is(err, ErrNoNodeToRemove)
	if err != nil && !oldPartIDNotFound {
		return nil, err
	}
	if !oldPartIDNotFound {
		if err = n.objectDelete(ctx, bktInfo, oldPartID); err != nil {
			n.log.Error("couldn't delete old part object", zap.Error(err),
				zap.String("cnrID", bktInfo.CID.EncodeToString()),
				zap.String("bucket name", bktInfo.Name),
				zap.String("objID", oldPartID.EncodeToString()))
		}
	}

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
		elements        []data.LinkObjectPayload
		creationTime    = TimeNow(ctx)
		currentPartHash = sha256.New()
	)

	if p.Encryption.Enabled() {
		attributes[AttributeDecryptedSize] = "0"
	}

	if n.neoFS.IsHomomorphicHashingEnabled() {
		tzHash = tz.New()
	}

	var objHashes []hash.Hash
	if tzHash != nil {
		objHashes = append(objHashes, tzHash)
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
	hashlessHeaderObject.SetOwnerID(&bktInfo.Owner)
	hashlessHeaderObject.SetAttributes(attrs...)
	hashlessHeaderObject.SetCreationEpoch(n.neoFS.CurrentEpoch())

	currentVersion := version.Current()
	hashlessHeaderObject.SetVersion(&currentVersion)

	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Attributes:   attributes,
		CreationTime: creationTime,
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			MultipartHashes: objHashes,
			HeaderObject:    &hashlessHeaderObject,
			PayloadHash:     sha256.New(),
		},
		Payload: bytes.NewBuffer(nil),
	}

	if n.neoFS.IsHomomorphicHashingEnabled() {
		prm.Multipart.HomoHash = tz.New()
	}

	id, err := n.multipartObjectPut(ctx, prm, bktInfo)
	if err != nil {
		return nil, err
	}

	elements = append(elements, data.LinkObjectPayload{OID: id, Size: 0})

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("upload zero part",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", bktInfo.Name), zap.Stringer("cid", bktInfo.CID),
		zap.String("multipart upload", id.String()),
		zap.Int("part number", 0), zap.String("object", p.Key), zap.Stringer("oid", id))

	partInfo := &data.PartInfo{
		Key: p.Key,
		// UploadID equals zero part ID intentionally.
		UploadID: id.String(),
		Number:   0,
		OID:      id,
		Size:     0,
		ETag:     hex.EncodeToString(currentPartHash.Sum(nil)),
		Created:  prm.CreationTime,
		Elements: elements,
	}

	// encoding hash.Hash state to save it in tree service.
	// the required interface is guaranteed according to the docs, so just cast without checks.
	binaryMarshaler := multipartHash.(encoding.BinaryMarshaler)
	partInfo.MultipartHash, err = binaryMarshaler.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalBinary: %w", err)
	}

	if tzHash != nil {
		binaryMarshaler = tzHash.(encoding.BinaryMarshaler)
		partInfo.HomoHash, err = binaryMarshaler.MarshalBinary()

		if err != nil {
			return nil, fmt.Errorf("marshalBinary: %w", err)
		}
	}

	return partInfo, nil
}

func (n *layer) finalizeZeroPart(ctx context.Context, bktInfo *data.BucketInfo, nodeID uint64, partInfo *data.PartInfo) error {
	oldPartID, err := n.treeService.AddPart(ctx, bktInfo, nodeID, partInfo)
	oldPartIDNotFound := errors.Is(err, ErrNoNodeToRemove)
	if err != nil && !oldPartIDNotFound {
		return err
	}

	if !oldPartIDNotFound {
		if err = n.objectDelete(ctx, bktInfo, oldPartID); err != nil {
			n.log.Error("couldn't delete old part object", zap.Error(err),
				zap.String("cnrID", bktInfo.CID.EncodeToString()),
				zap.String("bucket name", bktInfo.Name),
				zap.String("objID", oldPartID.EncodeToString()))
		}
	}

	return nil
}

func (n *layer) reUploadFollowingParts(ctx context.Context, uploadParams UploadPartParams, partID int, bktInfo *data.BucketInfo, multipartInfo *data.MultipartInfo) error {
	parts, err := n.treeService.GetPartsAfter(ctx, bktInfo, multipartInfo.ID, partID)
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

		for _, element := range part.Elements {
			elementObj, err = n.objectGet(ctx, bktInfo, element.OID)
			if err != nil {
				err = fmt.Errorf("get part oid=%s, element oid=%s: %w", part.OID.String(), element.OID.String(), err)
				break
			}

			if _, err = pipeWriter.Write(elementObj.Payload()); err != nil {
				err = fmt.Errorf("write part oid=%s, element oid=%s: %w", part.OID.String(), element.OID.String(), err)
				break
			}

			// The part contains all elements for Split chain and contains itself as well.
			// We mustn't remove it here, it will be removed on MultipartComplete.
			if part.OID == element.OID {
				continue
			}

			if deleteErr := n.objectDelete(ctx, bktInfo, element.OID); deleteErr != nil {
				n.log.Error(
					"couldn't delete object",
					zap.Error(deleteErr),
					zap.String("cnrID", bktInfo.CID.EncodeToString()),
					zap.String("uploadID", multipartInfo.UploadID),
					zap.Int("partNumber", part.Number),
					zap.String("part.OID", part.OID.String()),
					zap.String("part element OID", element.OID.String()),
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

		n.log.Debug("reUploadPart", zap.String("oid", part.OID.String()), zap.Int64("payload size", uploadParams.Size))
		if _, err := n.uploadPart(ctx, multipartInfo, &uploadParams); err != nil {
			return fmt.Errorf("upload id=%s: %w", part.OID.String(), err)
		}

		return nil
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("upload part oid=%s: %w", part.OID.String(), err)
	}

	// remove old object, we just re-uploaded a new one.
	if err := n.objectDelete(ctx, bktInfo, part.OID); err != nil {
		return fmt.Errorf("delete old id=%s: %w", part.OID.String(), err)
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

	n.log.Debug("reUploadPart", zap.String("oid", id.String()), zap.Uint64("payload size", obj.PayloadSize()))
	if _, err = n.uploadPart(ctx, multipartInfo, &uploadParams); err != nil {
		return fmt.Errorf("upload id=%s: %w", id.String(), err)
	}

	// remove old object, we just re-uploaded a new one.
	if err = n.objectDelete(ctx, bktInfo, id); err != nil {
		return fmt.Errorf("delete old id=%s: %w", id.String(), err)
	}

	return nil
}

func (n *layer) UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error) {
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
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
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, p.Info.Bkt, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}

		return nil, nil, fmt.Errorf("get multipart upload: %w", err)
	}

	// There are no parts which were uploaded in arbitrary order.
	if partNumber == 0 {
		n.log.Debug("no arbitrary order parts", zap.String("uploadID", p.Info.UploadID))

		// In case of all parts were uploaded subsequently, but some of them were re-uploaded.
		partNumber, err = n.getMinDuplicatedPartNumber(ctx, p.Info, multipartInfo)
		if err != nil {
			return nil, nil, fmt.Errorf("get min duplicated part number: %w", err)
		}
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
	var splitFirstID oid.ID

	if err = splitFirstID.DecodeString(multipartInfo.UploadID); err != nil {
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
			mObj.SetObjectID(element.OID)
			mObj.SetObjectSize(element.Size)
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

				if len(lastPart.MultipartHash) > 0 {
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

	header, err := n.prepareMultipartHeadObject(ctx, prmHeaderObject, multipartHash, homoHash, uint64(multipartObjetSize))
	if err != nil {
		return nil, nil, err
	}

	// last part
	prm := PrmObjectCreate{
		Container:    p.Info.Bkt.CID,
		Creator:      p.Info.Bkt.Owner,
		Filepath:     p.Info.Key,
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

	bktSettings, err := n.GetBucketSettings(ctx, p.Info.Bkt)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't get versioning settings object: %w", err)
	}

	headerObjectID, _ := header.ID()

	// the "big object" is not presented in system, but we have to put correct info about it and its version.

	newVersion := &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			FilePath: p.Info.Key,
			Size:     multipartObjetSize,
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

	return uploadData, extObjInfo, n.treeService.DeleteMultipartUpload(ctx, p.Info.Bkt, multipartInfo.ID)
}

func (n *layer) ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error) {
	var result ListMultipartUploadsInfo
	if p.MaxUploads == 0 {
		return &result, nil
	}

	multipartInfos, err := n.treeService.GetMultipartUploadsByPrefix(ctx, p.Bkt, p.Prefix)
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

func (n *layer) AbortMultipartUpload(ctx context.Context, p *UploadInfoParams) error {
	multipartInfo, parts, err := n.getUploadParts(ctx, p)
	if err != nil {
		return err
	}

	for _, info := range parts {
		if err = n.objectDelete(ctx, p.Bkt, info.OID); err != nil {
			n.log.Warn("couldn't delete part", zap.String("cid", p.Bkt.CID.EncodeToString()),
				zap.String("oid", info.OID.EncodeToString()), zap.Int("part number", info.Number), zap.Error(err))
		}
	}

	return n.treeService.DeleteMultipartUpload(ctx, p.Bkt, multipartInfo.ID)
}

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error) {
	var res ListPartsInfo
	multipartInfo, partsInfo, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, err
	}

	encInfo := FormEncryptionInfo(multipartInfo.Meta)
	if err = p.Info.Encryption.MatchObjectEncryption(encInfo); err != nil {
		n.log.Warn("mismatched obj encryptionInfo", zap.Error(err))
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidEncryptionParameters)
	}

	res.Owner = multipartInfo.Owner
	res.OwnerPubKey = multipartInfo.OwnerPubKey

	parts := make([]*Part, 0, len(partsInfo))

	for _, partInfo := range partsInfo {
		// We need to skip this part, it is an artificial and not a client uploaded.
		if partInfo.Number == 0 {
			continue
		}

		parts = append(parts, &Part{
			ETag:         partInfo.ETag,
			LastModified: partInfo.Created.UTC().Format(time.RFC3339),
			PartNumber:   partInfo.Number,
			Size:         partInfo.Size,
		})
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
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, p.Bkt, p.Key, p.UploadID)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrNoSuchUpload)
		}
		return nil, nil, err
	}

	parts, err := n.treeService.GetParts(ctx, p.Bkt, multipartInfo.ID)
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
		IsDir:       isDir,
		Key:         key,
		UploadID:    uploadInfo.UploadID,
		Owner:       uploadInfo.Owner,
		OwnerPubKey: uploadInfo.OwnerPubKey,
		Created:     uploadInfo.Created,
	}
}

func (n *layer) manualSlice(ctx context.Context, bktInfo *data.BucketInfo, prm PrmObjectCreate, splitFirstID, splitPreviousID oid.ID, chunk []byte, payloadReader io.Reader) (oid.ID, []data.LinkObjectPayload, error) {
	var (
		totalBytes int
		id         oid.ID
		err        error
		elements   []data.LinkObjectPayload
	)
	// slice part manually. Simultaneously considering the part is a single object for user.
	for {
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

			id, err = n.multipartObjectPut(ctx, prm, bktInfo)
			if err != nil {
				return id, nil, fmt.Errorf("multipart object put: %w", err)
			}

			splitPreviousID = id
			elements = append(elements, data.LinkObjectPayload{OID: id, Size: uint32(nBts)})
		}

		if readErr == nil {
			continue
		}

		// If an EOF happens after reading fewer than min bytes, ReadAtLeast returns ErrUnexpectedEOF.
		// We have the whole payload.
		if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return id, nil, fmt.Errorf("read payload chunk: %w", err)
		}

		break
	}

	return id, elements, nil
}

// uploadPartAsSlot uploads multipart part, but without correct link to previous part because we don't have it.
// It uses zero part as pivot. Actual link will be set on CompleteMultipart.
func (n *layer) uploadPartAsSlot(ctx context.Context, params uploadPartAsSlotParams) (*data.ObjectInfo, error) {
	var (
		id            oid.ID
		elements      []data.LinkObjectPayload
		multipartHash = sha256.New()
	)

	params.attributes[headerS3MultipartUpload] = params.multipartInfo.UploadID
	params.attributes[headerS3MultipartNumber] = strconv.FormatInt(int64(params.uploadPartParams.PartNumber), 10)
	params.attributes[headerS3MultipartCreated] = strconv.FormatInt(time.Now().UnixNano(), 10)

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
		Key:      params.uploadPartParams.Info.Key,
		UploadID: params.uploadPartParams.Info.UploadID,
		Number:   params.uploadPartParams.PartNumber,
		OID:      id,
		Size:     params.decSize,
		ETag:     hex.EncodeToString(objHashBts),
		Created:  prm.CreationTime,
		Elements: elements,
	}

	// encoding hash.Hash state to save it in tree service.
	// the required interface is guaranteed according to the docs, so just cast without checks.
	binaryMarshaler := multipartHash.(encoding.BinaryMarshaler)
	partInfo.MultipartHash, err = binaryMarshaler.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalBinary: %w", err)
	}

	if params.tzHash != nil {
		binaryMarshaler = params.tzHash.(encoding.BinaryMarshaler)
		partInfo.HomoHash, err = binaryMarshaler.MarshalBinary()

		if err != nil {
			return nil, fmt.Errorf("marshalBinary: %w", err)
		}
	}

	oldPartID, err := n.treeService.AddPart(ctx, params.bktInfo, params.multipartInfo.ID, partInfo)
	oldPartIDNotFound := errors.Is(err, ErrNoNodeToRemove)
	if err != nil && !oldPartIDNotFound {
		return nil, err
	}

	if !oldPartIDNotFound {
		if err = n.objectDelete(ctx, params.bktInfo, oldPartID); err != nil {
			n.log.Error("couldn't delete old part object", zap.Error(err),
				zap.String("cnrID", params.bktInfo.CID.EncodeToString()),
				zap.String("bucket name", params.bktInfo.Name),
				zap.String("objID", oldPartID.EncodeToString()))
		}
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

func (n *layer) getSlotAttributes(obj object.Object) (*slotAttributes, error) {
	var (
		attributes slotAttributes
		err        error
	)

	for _, attr := range obj.Attributes() {
		switch attr.Key() {
		case headerS3MultipartNumber:
			attributes.PartNumber, err = strconv.ParseInt(attr.Value(), 10, 64)
		case headerS3MultipartCreated:
			attributes.CreatedAt, err = strconv.ParseInt(attr.Value(), 10, 64)
		case object.AttributeFilePath:
			attributes.FilePath = attr.Value()
		default:
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("parse header: %w", err)
		}
	}

	return &attributes, nil
}

func (n *layer) getFirstArbitraryPart(ctx context.Context, uploadID string, bucketInfo *data.BucketInfo) (int64, error) {
	var filters object.SearchFilters
	filters.AddFilter(headerS3MultipartUpload, uploadID, object.MatchStringEqual)

	var prmSearch = PrmObjectSearch{
		Container: bucketInfo.CID,
		Filters:   filters,
	}

	n.prepareAuthParameters(ctx, &prmSearch.PrmAuth, bucketInfo.Owner)

	oids, err := n.neoFS.SearchObjects(ctx, prmSearch)
	if err != nil {
		return 0, fmt.Errorf("search objects: %w", err)
	}

	if len(oids) == 0 {
		return 0, nil
	}

	var partNumber int64

	for _, id := range oids {
		head, err := n.objectHead(ctx, bucketInfo, id)
		if err != nil {
			return 0, fmt.Errorf("object head: %w", err)
		}

		attributes, err := n.getSlotAttributes(*head)
		if err != nil {
			return 0, fmt.Errorf("get slot attributes: %w", err)
		}

		if partNumber == 0 {
			partNumber = attributes.PartNumber
		} else {
			partNumber = min(partNumber, attributes.PartNumber)
		}
	}

	return partNumber, nil
}

func (n *layer) getMinDuplicatedPartNumber(ctx context.Context, p *UploadInfoParams, multipartInfo *data.MultipartInfo) (int64, error) {
	parts, err := n.treeService.GetParts(ctx, p.Bkt, multipartInfo.ID)
	if err != nil {
		return 0, fmt.Errorf("get parts: %w", err)
	}

	uniqParts := make(map[int]int, len(parts))
	for _, part := range parts {
		uniqParts[part.Number] += 1
	}

	var firstNonUniqPartNumber int
	for partNumber, v := range uniqParts {
		if v > 1 {
			if firstNonUniqPartNumber == 0 {
				firstNonUniqPartNumber = partNumber
			} else {
				firstNonUniqPartNumber = min(firstNonUniqPartNumber, partNumber)
			}
		}
	}

	return int64(firstNonUniqPartNumber), nil
}
