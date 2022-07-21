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

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/internal/misc"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	UploadIDAttributeName         = "S3-Upload-Id"
	UploadPartNumberAttributeName = "S3-Upload-Part-Number"
	UploadKeyAttributeName        = "S3-Upload-Key"
	UploadCompletedParts          = "S3-Completed-Parts"
	UploadPartKeyPrefix           = ".upload-"

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
		Info       *UploadInfoParams
		Header     map[string]string
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
	info := &data.MultipartInfo{
		Key:      p.Info.Key,
		UploadID: p.Info.UploadID,
		Owner:    n.Owner(ctx),
		Created:  time.Now(),
		Meta:     make(map[string]string, len(p.Header)+len(p.ACLHeaders)+len(p.TagSet)),
	}

	for key, val := range p.Header {
		info.Meta[metaPrefix+key] = val
	}

	for key, val := range p.ACLHeaders {
		info.Meta[aclPrefix+key] = val
	}

	for key, val := range p.TagSet {
		info.Meta[tagPrefix+key] = val
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
	prm := PrmObjectCreate{
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
		Size:    p.Size,
		Created: time.Now(),
		HashSum: hex.EncodeToString(hash),
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

	metadata := make(map[string]string)
	appendUploadHeaders(metadata, p.Info.UploadID, p.Info.Key, p.PartNumber)

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

	parts []*data.ObjectInfo
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

	x.prm.objInfo = x.parts[0]

	x.curReader, err = x.layer.initObjectPayloadReader(x.ctx, x.prm)
	if err != nil {
		return n, fmt.Errorf("init payload reader for the next part: %w", err)
	}

	x.parts = x.parts[1:]

	next, err := x.Read(p[n:])

	return n + next, err
}

func (n *layer) CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*data.ObjectInfo, error) {
	var (
		obj            *data.ObjectInfo
		partsAttrValue string
	)

	for i := 1; i < len(p.Parts); i++ {
		if p.Parts[i].PartNumber <= p.Parts[i-1].PartNumber {
			return nil, errors.GetAPIError(errors.ErrInvalidPartOrder)
		}
	}

	_, objects, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, err
	}

	if len(objects) == 1 {
		obj, err = n.headLastVersionIfNotDeleted(ctx, p.Info.Bkt, p.Info.Key)
		if err != nil {
			if errors.IsS3Error(err, errors.ErrNoSuchKey) {
				return nil, errors.GetAPIError(errors.ErrInvalidPart)
			}
			return nil, err
		}
		if obj != nil && obj.Headers[UploadIDAttributeName] == p.Info.UploadID {
			return obj, nil
		}
		return nil, errors.GetAPIError(errors.ErrInvalidPart)
	}

	if _, ok := objects[0]; !ok {
		n.log.Error("could not get init multipart upload",
			zap.Stringer("bucket id", p.Info.Bkt.CID),
			zap.String("uploadID", misc.SanitizeString(p.Info.UploadID)),
			zap.String("uploadKey", p.Info.Key),
		)
		// we return InternalError because if we are here it means we've checked InitPart in handler before and
		// received successful result, it's strange we didn't get the InitPart again
		return nil, errors.GetAPIError(errors.ErrInternalError)
	}

	// keep in mind objects[0] is the init part
	if len(objects) <= len(p.Parts) {
		return nil, errors.GetAPIError(errors.ErrInvalidPart)
	}

	parts := make([]*data.ObjectInfo, 0, len(p.Parts))

	for i, part := range p.Parts {
		info := objects[part.PartNumber]
		if info == nil || part.ETag != info.HashSum {
			return nil, errors.GetAPIError(errors.ErrInvalidPart)
		}
		// for the last part we have no minimum size limit
		if i != len(p.Parts)-1 && info.Size < uploadMinSize {
			return nil, errors.GetAPIError(errors.ErrEntityTooSmall)
		}
		parts = append(parts, info)
		partsAttrValue += strconv.Itoa(part.PartNumber) + "=" + strconv.FormatInt(info.Size, 10) + ","
	}

	initMetadata := objects[0].Headers
	if len(objects[0].ContentType) != 0 {
		initMetadata[api.ContentType] = objects[0].ContentType
	}

	/* We will keep "S3-Upload-Id" attribute in a completed object to determine if it is a "common" object or a completed object.
	We will need to differ these objects if something goes wrong during completing multipart upload.
	I.e. we had completed the object but didn't put tagging/acl for some reason */
	delete(initMetadata, UploadPartNumberAttributeName)
	delete(initMetadata, UploadKeyAttributeName)
	delete(initMetadata, attrVersionsIgnore)
	delete(initMetadata, objectSystemAttributeName)
	delete(initMetadata, versionsUnversionedAttr)

	initMetadata[UploadCompletedParts] = partsAttrValue[:len(partsAttrValue)-1]

	r := &multiObjectReader{
		ctx:   ctx,
		layer: n,
		parts: parts,
	}

	r.prm.bktInfo = p.Info.Bkt

	obj, err = n.PutObject(ctx, &PutObjectParams{
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

		return nil, errors.GetAPIError(errors.ErrInternalError)
	}

	for partNum, objInfo := range objects {
		if partNum == 0 {
			continue
		}
		if err = n.objectDelete(ctx, p.Info.Bkt, objInfo.ID); err != nil {
			n.log.Warn("could not delete upload part",
				zap.Stringer("object id", objInfo.ID),
				zap.Stringer("bucket id", p.Info.Bkt.CID),
				zap.Error(err))
		}
		n.systemCache.Delete(systemObjectKey(p.Info.Bkt, FormUploadPartName(p.Info.UploadID, p.Info.Key, partNum)))
	}

	return obj, nil
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
	_, objects, err := n.getUploadParts(ctx, p)
	if err != nil {
		return err
	}

	for _, info := range objects {
		if err = n.objectDelete(ctx, p.Bkt, info.ID); err != nil {
			return err
		}
	}

	return nil
}

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error) {
	var res ListPartsInfo
	multipartInfo, objs, err := n.getUploadParts(ctx, p.Info) // todo consider listing without head object from NeoFS
	if err != nil {
		return nil, err
	}

	res.Owner = multipartInfo.Owner

	parts := make([]*Part, 0, len(objs))

	for num, objInfo := range objs {
		if num == 0 {
			continue
		}
		parts = append(parts, &Part{
			ETag:         objInfo.HashSum,
			LastModified: objInfo.Created.UTC().Format(time.RFC3339),
			PartNumber:   num,
			Size:         objInfo.Size,
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

func (n *layer) GetUploadInitInfo(ctx context.Context, p *UploadInfoParams) (*data.ObjectInfo, error) {
	info, err := n.HeadSystemObject(ctx, p.Bkt, FormUploadPartName(p.UploadID, p.Key, 0))
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchKey) {
			return nil, errors.GetAPIError(errors.ErrNoSuchUpload)
		}
		return nil, err
	}

	return info, nil
}

func (n *layer) getUploadParts(ctx context.Context, p *UploadInfoParams) (*data.MultipartInfo, map[int]*data.ObjectInfo, error) {
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

	res := make(map[int]*data.ObjectInfo)
	var addr oid.Address
	addr.SetContainer(p.Bkt.CID)
	for _, part := range parts {
		addr.SetObject(part.OID)
		objInfo := n.objCache.GetObject(addr)
		if objInfo == nil {
			meta, err := n.objectHead(ctx, p.Bkt, part.OID)
			if err != nil {
				n.log.Warn("couldn't head a part of upload",
					zap.String("object id", part.OID.EncodeToString()),
					zap.String("bucket id", p.Bkt.CID.EncodeToString()),
					zap.Error(err))
				continue
			}
			objInfo = objInfoFromMeta(p.Bkt, meta)
		}

		res[part.Number] = objInfo
		if err = n.objCache.PutObject(objInfo); err != nil {
			n.log.Warn("couldn't cache upload part", zap.Error(err))
		}
	}

	return multipartInfo, res, nil
}

func FormUploadPartName(uploadID, key string, partNumber int) string {
	return UploadPartKeyPrefix + uploadID + "-" + key + "-" + strconv.Itoa(partNumber)
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

func appendUploadHeaders(metadata map[string]string, uploadID, key string, partNumber int) {
	metadata[UploadIDAttributeName] = uploadID
	metadata[UploadPartNumberAttributeName] = strconv.Itoa(partNumber)
}
