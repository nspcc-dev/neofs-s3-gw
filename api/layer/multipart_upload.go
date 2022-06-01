package layer

import (
	"context"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/internal/misc"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	UploadIDAttributeName         = "S3-Upload-Id"
	UploadPartNumberAttributeName = "S3-Upload-Part-Number"
	UploadCompletedPartsCount     = "S3-Completed-Parts-Count"

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
		UploadID string
		Bkt      *data.BucketInfo
		Key      string
	}

	CreateMultipartParams struct {
		Info   *UploadInfoParams
		Header map[string]string
		Data   *UploadData
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
		Key:      p.Info.Key,
		UploadID: p.Info.UploadID,
		Owner:    n.Owner(ctx),
		Created:  time.Now(),
		Meta:     make(map[string]string, metaSize),
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

	return n.treeService.CreateMultipartUpload(ctx, &p.Info.Bkt.CID, info)
}

func (n *layer) UploadPart(ctx context.Context, p *UploadPartParams) (string, error) {
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, &p.Info.Bkt.CID, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if stderrors.Is(err, ErrNodeNotFound) {
			return "", errors.GetAPIError(errors.ErrNoSuchUpload)
		}
		return "", err
	}

	if p.Size > uploadMaxSize {
		return "", errors.GetAPIError(errors.ErrEntityTooLarge)
	}

	objInfo, err := n.uploadPart(ctx, multipartInfo, p)
	if err != nil {
		return "", err
	}

	return objInfo.HashSum, nil
}

func (n *layer) uploadPart(ctx context.Context, multipartInfo *data.MultipartInfo, p *UploadPartParams) (*data.ObjectInfo, error) {
	bktInfo := p.Info.Bkt
	prm := neofs.PrmObjectCreate{
		Container:  bktInfo.CID,
		Creator:    bktInfo.Owner,
		Attributes: make([][2]string, 2),
		Payload:    p.Reader,
	}

	prm.Attributes[0][0], prm.Attributes[0][1] = UploadIDAttributeName, p.Info.UploadID
	prm.Attributes[1][0], prm.Attributes[1][1] = UploadPartNumberAttributeName, strconv.Itoa(p.PartNumber)

	id, hash, err := n.objectPutAndHash(ctx, prm, bktInfo)
	if err != nil {
		return nil, err
	}

	partInfo := &data.PartInfo{
		Key:      p.Info.Key,
		UploadID: p.Info.UploadID,
		Number:   p.PartNumber,
		OID:      *id,
		Size:     p.Size,
		ETag:     hex.EncodeToString(hash),
		Created:  time.Now(),
	}

	oldPartID, err := n.treeService.AddPart(ctx, &bktInfo.CID, multipartInfo.ID, partInfo)
	if err != nil {
		return nil, err
	}
	if oldPartID != nil {
		if err = n.objectDelete(ctx, bktInfo, *oldPartID); err != nil {
			n.log.Error("couldn't delete old part object", zap.Error(err),
				zap.String("cnrID", bktInfo.CID.EncodeToString()),
				zap.String("bucket name", bktInfo.Name),
				zap.String("objID", oldPartID.EncodeToString()))
		}
	}

	objInfo := &data.ObjectInfo{
		ID:  *id,
		CID: bktInfo.CID,

		Owner:   bktInfo.Owner,
		Bucket:  bktInfo.Name,
		Size:    partInfo.Size,
		Created: partInfo.Created,
		HashSum: partInfo.ETag,
	}

	if err = n.objCache.PutObject(objInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return objInfo, nil
}

func (n *layer) UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error) {
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, &p.Info.Bkt.CID, p.Info.Key, p.Info.UploadID)
	if err != nil {
		if stderrors.Is(err, ErrNodeNotFound) {
			return nil, errors.GetAPIError(errors.ErrNoSuchUpload)
		}
		return nil, err
	}

	size := p.SrcObjInfo.Size
	if p.Range != nil {
		size = int64(p.Range.End - p.Range.Start + 1)
		if p.Range.End > uint64(p.SrcObjInfo.Size) {
			return nil, errors.GetAPIError(errors.ErrInvalidCopyPartRangeSource)
		}
	}
	if size > uploadMaxSize {
		return nil, errors.GetAPIError(errors.ErrEntityTooLarge)
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

	return n.uploadPart(ctx, multipartInfo, params)
}

// implements io.Reader of payloads of the object list stored in the NeoFS network.
type multiObjectReader struct {
	ctx context.Context

	layer *layer

	prm getParams

	curReader io.Reader

	parts []*data.PartInfo
}

func (x *multiObjectReader) Read(p []byte) (n int, err error) {
	if x.curReader != nil {
		n, err = x.curReader.Read(p)
		if !stderrors.Is(err, io.EOF) {
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

func (n *layer) CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*UploadData, *data.ObjectInfo, error) {
	for i := 1; i < len(p.Parts); i++ {
		if p.Parts[i].PartNumber <= p.Parts[i-1].PartNumber {
			return nil, nil, errors.GetAPIError(errors.ErrInvalidPartOrder)
		}
	}

	multipartInfo, partsInfo, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, nil, err
	}

	if len(partsInfo) < len(p.Parts) {
		return nil, nil, errors.GetAPIError(errors.ErrInvalidPart)
	}

	parts := make([]*data.PartInfo, 0, len(p.Parts))

	for i, part := range p.Parts {
		partInfo := partsInfo[part.PartNumber]
		if part.ETag != partInfo.ETag {
			return nil, nil, errors.GetAPIError(errors.ErrInvalidPart)
		}
		// for the last part we have no minimum size limit
		if i != len(p.Parts)-1 && partInfo.Size < uploadMinSize {
			return nil, nil, errors.GetAPIError(errors.ErrEntityTooSmall)
		}
		parts = append(parts, partInfo)
	}

	initMetadata := make(map[string]string, len(multipartInfo.Meta)+1)
	initMetadata[UploadCompletedPartsCount] = strconv.Itoa(len(p.Parts))
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

	r := &multiObjectReader{
		ctx:   ctx,
		layer: n,
		parts: parts,
	}

	r.prm.bktInfo = p.Info.Bkt

	obj, err := n.PutObject(ctx, &PutObjectParams{
		BktInfo: p.Info.Bkt,
		Object:  p.Info.Key,
		Reader:  r,
		Header:  initMetadata,
	})
	if err != nil {
		n.log.Error("could not put a completed object (multipart upload)",
			zap.String("uploadID", misc.SanitizeString(p.Info.UploadID)),
			zap.String("uploadKey", p.Info.Key),
			zap.Error(err))

		return nil, nil, errors.GetAPIError(errors.ErrInternalError)
	}

	var addr oid.Address
	addr.SetContainer(p.Info.Bkt.CID)
	for _, partInfo := range partsInfo {
		if err = n.objectDelete(ctx, p.Info.Bkt, partInfo.OID); err != nil {
			n.log.Warn("could not delete upload part",
				zap.Stringer("object id", &partInfo.OID),
				zap.Stringer("bucket id", &p.Info.Bkt.CID),
				zap.Error(err))
		}
		addr.SetObject(partInfo.OID)
		n.objCache.Delete(addr)
	}

	return uploadData, obj, n.treeService.DeleteMultipartUpload(ctx, &p.Info.Bkt.CID, multipartInfo.ID)
}

func (n *layer) ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) (*ListMultipartUploadsInfo, error) {
	var result ListMultipartUploadsInfo
	if p.MaxUploads == 0 {
		return &result, nil
	}

	multipartInfos, err := n.treeService.GetMultipartUploadsByPrefix(ctx, &p.Bkt.CID, p.Prefix)
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
				zap.String("oid", info.OID.EncodeToString()), zap.Int("part number", info.Number))
		}
	}

	return n.treeService.DeleteMultipartUpload(ctx, &p.Bkt.CID, multipartInfo.ID)
}

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error) {
	var res ListPartsInfo
	multipartInfo, partsInfo, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, err
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
	multipartInfo, err := n.treeService.GetMultipartUpload(ctx, &p.Bkt.CID, p.Key, p.UploadID)
	if err != nil {
		if stderrors.Is(err, ErrNodeNotFound) {
			return nil, nil, errors.GetAPIError(errors.ErrNoSuchUpload)
		}
		return nil, nil, err
	}

	parts, err := n.treeService.GetParts(ctx, &p.Bkt.CID, multipartInfo.ID)
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
