package layer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sio"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/tzhash/tz"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
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

func (n *layer) CreateMultipartUpload(ctx context.Context, p *CreateMultipartParams) error {
	metaSize := len(p.Header)
	if p.Data != nil {
		metaSize += len(p.Data.ACLHeaders)
		metaSize += len(p.Data.TagSet)
	}

	info := &data.MultipartInfo{
		Key:          p.Info.Key,
		UploadID:     p.Info.UploadID,
		Owner:        n.Owner(ctx),
		Created:      TimeNow(ctx),
		Meta:         make(map[string]string, metaSize),
		CopiesNumber: p.CopiesNumber,
		SplitID:      object.NewSplitID().String(),
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

	return n.treeService.CreateMultipartUpload(ctx, p.Info.Bkt, info)
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

	if err = n.reUploadFollowingParts(ctx, *p, p.PartNumber, p.Info.Bkt, multipartInfo); err != nil {
		return "", fmt.Errorf("reuploading parts: %w", err)
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
		attributes    [][2]string
	)

	if p.Info.Encryption.Enabled() {
		r, encSize, err := encryptionReader(p.Reader, uint64(p.Size), p.Info.Encryption.Key())
		if err != nil {
			return nil, fmt.Errorf("failed to create ecnrypted reader: %w", err)
		}
		attributes = append(attributes, [2]string{AttributeDecryptedSize, strconv.FormatInt(p.Size, 10)})
		payloadReader = r
		p.Size = int64(encSize)
	}

	var (
		splitPreviousID      oid.ID
		isSetSplitPreviousID bool
		multipartHash        = sha256.New()
		tzHash               hash.Hash
	)

	if n.neoFS.IsHomomorphicHashingEnabled() {
		tzHash = tz.New()
	}

	lastPart, err := n.treeService.GetLastPart(ctx, bktInfo, multipartInfo.ID)
	if err != nil {
		// if ErrPartListIsEmpty, there is the first part of multipart.
		if !errors.Is(err, ErrPartListIsEmpty) {
			return nil, fmt.Errorf("getLastPart: %w", err)
		}
	} else {
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

		isSetSplitPreviousID = true
		splitPreviousID = lastPart.OID
	}

	var (
		id           oid.ID
		elements     []oid.ID
		creationTime = TimeNow(ctx)
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
			SplitID:         multipartInfo.SplitID,
			MultipartHashes: objHashes,
		},
	}

	chunk := n.buffers.Get().(*[]byte)

	// slice part manually. Simultaneously considering the part is a single object for user.
	for {
		if isSetSplitPreviousID {
			prm.Multipart.SplitPreviousID = &splitPreviousID
		}

		nBts, readErr := io.ReadAtLeast(payloadReader, *chunk, len(*chunk))
		if nBts > 0 {
			prm.Payload = bytes.NewReader((*chunk)[:nBts])
			prm.PayloadSize = uint64(nBts)

			id, _, err = n.objectPutAndHash(ctx, prm, bktInfo)
			if err != nil {
				return nil, err
			}

			isSetSplitPreviousID = true
			splitPreviousID = id
			elements = append(elements, id)
		}

		if readErr == nil {
			continue
		}

		// If an EOF happens after reading fewer than min bytes, ReadAtLeast returns ErrUnexpectedEOF.
		// We have the whole payload.
		if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read payload chunk: %w", err)
		}

		break
	}
	n.buffers.Put(chunk)

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("upload part",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", bktInfo.Name), zap.Stringer("cid", bktInfo.CID),
		zap.String("multipart upload", p.Info.UploadID),
		zap.Int("part number", p.PartNumber), zap.String("object", p.Info.Key), zap.Stringer("oid", id))

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

		Owner:   bktInfo.Owner,
		Bucket:  bktInfo.Name,
		Size:    partInfo.Size,
		Created: partInfo.Created,
		HashSum: partInfo.ETag,
	}

	return objInfo, nil
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

		if err = n.reUploadPart(ctx, uploadParams, part.OID, bktInfo, multipartInfo); err != nil {
			return fmt.Errorf("reupload number=%d: %w", part.Number, err)
		}
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

	if err = n.reUploadFollowingParts(ctx, *params, p.PartNumber, p.Info.Bkt, multipartInfo); err != nil {
		return nil, fmt.Errorf("reuploading parts: %w", err)
	}

	return objInfo, nil
}

func (n *layer) CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*UploadData, *data.ExtendedObjectInfo, error) {
	for i := 1; i < len(p.Parts); i++ {
		if p.Parts[i].PartNumber <= p.Parts[i-1].PartNumber {
			return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPartOrder)
		}
	}

	multipartInfo, partsInfo, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, nil, err
	}
	encInfo := FormEncryptionInfo(multipartInfo.Meta)

	if len(partsInfo) < len(p.Parts) {
		return nil, nil, s3errors.GetAPIError(s3errors.ErrInvalidPart)
	}

	var multipartObjetSize int64
	var encMultipartObjectSize uint64
	var lastPartID int
	var children []oid.ID
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

		children = append(children, partInfo.Elements...)
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
			SplitID:         multipartInfo.SplitID,
			SplitPreviousID: &splitPreviousID,
			HeaderObject:    header,
		},
		Payload: bytes.NewBuffer(nil),
	}

	lastPartObjID, _, err := n.objectPutAndHash(ctx, prm, p.Info.Bkt)
	if err != nil {
		return nil, nil, err
	}

	children = append(children, lastPartObjID)

	// linking object
	prm = PrmObjectCreate{
		Container:    p.Info.Bkt.CID,
		Creator:      p.Info.Bkt.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: multipartInfo.CopiesNumber,
		Multipart: &Multipart{
			SplitID:      multipartInfo.SplitID,
			HeaderObject: header,
			Children:     children,
		},
		Payload: bytes.NewBuffer(nil),
	}

	_, _, err = n.objectPutAndHash(ctx, prm, p.Info.Bkt)
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

	if newVersion.ID, err = n.treeService.AddVersion(ctx, p.Info.Bkt, newVersion); err != nil {
		return nil, nil, fmt.Errorf("couldn't add multipart new verion to tree service: %w", err)
	}

	n.cache.CleanListCacheEntriesContainingObject(p.Info.Key, p.Info.Bkt.CID)

	objInfo := &data.ObjectInfo{
		ID:          headerObjectID,
		CID:         p.Info.Bkt.CID,
		Owner:       p.Info.Bkt.Owner,
		Bucket:      p.Info.Bkt.Name,
		Name:        p.Info.Key,
		Size:        multipartObjetSize,
		Created:     prm.CreationTime,
		Headers:     initMetadata,
		ContentType: initMetadata[api.ContentType],
		HashSum:     newVersion.ETag,
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
	slices.SortFunc(parts, func(a, b *data.PartInfo) int {
		if a.Number < b.Number {
			return -1
		}

		if a.ServerCreated.Before(b.ServerCreated) {
			return -1
		}

		if a.ServerCreated.Equal(b.ServerCreated) {
			return 0
		}

		return 1
	})

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
