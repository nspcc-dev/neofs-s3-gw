package layer

import (
	"context"
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
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

const (
	UploadIDAttributeName         = "S3-Upload-Id"
	UploadPartNumberAttributeName = "S3-Upload-Part-Number"
	UploadKeyAttributeName        = "S3-Upload-Key"
	UploadCompletedParts          = "S3-Completed-Parts"
	UploadPartKeyPrefix           = ".upload-"

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

	UploadPartParams struct {
		Info       *UploadInfoParams
		PartNumber int
		Size       int64
		Reader     io.Reader
		Header     map[string]string
	}

	UploadCopyParams struct {
		Info       *UploadInfoParams
		SrcObjInfo *data.ObjectInfo
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

func (n *layer) UploadPart(ctx context.Context, p *UploadPartParams) (*data.ObjectInfo, error) {
	if p.PartNumber != 0 {
		if _, err := n.GetUploadInitInfo(ctx, p.Info); err != nil {
			return nil, err
		}
	}

	if p.Size > uploadMaxSize {
		return nil, errors.GetAPIError(errors.ErrEntityTooLarge)
	}

	if p.Header == nil {
		p.Header = make(map[string]string)
	}

	appendUploadHeaders(p.Header, p.Info.UploadID, p.Info.Key, p.PartNumber)

	params := &PutSystemObjectParams{
		BktInfo:  p.Info.Bkt,
		ObjName:  FormUploadPartName(p.Info.UploadID, p.Info.Key, p.PartNumber),
		Metadata: p.Header,
		Prefix:   "",
		Reader:   p.Reader,
		Size:     p.Size,
	}

	return n.PutSystemObject(ctx, params)
}

func (n *layer) UploadPartCopy(ctx context.Context, p *UploadCopyParams) (*data.ObjectInfo, error) {
	if _, err := n.GetUploadInitInfo(ctx, p.Info); err != nil {
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
		err := n.GetObject(ctx, &GetObjectParams{
			ObjectInfo: p.SrcObjInfo,
			Writer:     pw,
			Range:      p.Range,
		})

		if err = pw.CloseWithError(err); err != nil {
			n.log.Error("could not get object", zap.Error(err))
		}
	}()

	return n.PutSystemObject(ctx, &PutSystemObjectParams{
		BktInfo:  p.Info.Bkt,
		ObjName:  FormUploadPartName(p.Info.UploadID, p.Info.Key, p.PartNumber),
		Metadata: metadata,
		Prefix:   "",
		Reader:   pr,
		Size:     size,
	})
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

	x.prm.oid = x.parts[0].ID

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

	objects, err := n.getUploadParts(ctx, p.Info)
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

	r.prm.cid = p.Info.Bkt.CID

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
		if err = n.objectDelete(ctx, p.Info.Bkt.CID, objInfo.ID); err != nil {
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

	f := &findParams{
		attr: [2]string{UploadPartNumberAttributeName, "0"},
		cid:  p.Bkt.CID,
	}

	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}

	uploads := make([]*UploadInfo, 0, len(ids))
	uniqDirs := make(map[string]struct{})

	for i := range ids {
		meta, err := n.objectHead(ctx, p.Bkt.CID, ids[i])
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", &ids[i]),
				zap.Stringer("bucket id", p.Bkt.CID),
				zap.Error(err))
			continue
		}
		info := uploadInfoFromMeta(meta, p.Prefix, p.Delimiter)
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
	objects, err := n.getUploadParts(ctx, p)
	if err != nil {
		return err
	}

	for _, info := range objects {
		err := n.objectDelete(ctx, info.CID, info.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) (*ListPartsInfo, error) {
	var res ListPartsInfo
	objs, err := n.getUploadParts(ctx, p.Info)
	if err != nil {
		return nil, err
	}

	res.Owner = objs[0].Owner

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

func (n *layer) getUploadParts(ctx context.Context, p *UploadInfoParams) (map[int]*data.ObjectInfo, error) {
	// we search by UploadID attribute because parts are system objects which have system name not filename
	// and search in attributes by prefix is not supported
	f := &findParams{
		attr: [2]string{UploadIDAttributeName, p.UploadID},
		cid:  p.Bkt.CID,
	}

	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}

	res := make(map[int]*data.ObjectInfo)

	for i := range ids {
		meta, err := n.objectHead(ctx, p.Bkt.CID, ids[i])
		if err != nil {
			n.log.Warn("couldn't head a part of upload",
				zap.Stringer("object id", &ids[i]),
				zap.Stringer("bucket id", p.Bkt.CID),
				zap.Error(err))
			continue
		}
		info := objInfoFromMeta(p.Bkt, meta)
		// skip objects which are completed by "complete-multipart-upload" because they have "s3-Upload-Id" attribute
		if !isSystem(info) {
			continue
		}
		numStr := info.Headers[UploadPartNumberAttributeName]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			return nil, errors.GetAPIError(errors.ErrInternalError)
		}
		res[num] = info
		if err = n.systemCache.PutObject(systemObjectKey(p.Bkt, FormUploadPartName(p.UploadID, p.Key, num)), info); err != nil {
			n.log.Warn("couldn't cache upload part", zap.Error(err))
		}
	}

	if len(res) == 0 {
		return nil, errors.GetAPIError(errors.ErrNoSuchUpload)
	}

	return res, nil
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

func uploadInfoFromMeta(meta *object.Object, prefix, delimiter string) *UploadInfo {
	var (
		isDir       bool
		creation    time.Time
		userHeaders = userHeaders(meta.Attributes())
		key         = userHeaders[UploadKeyAttributeName]
	)

	if !strings.HasPrefix(key, prefix) {
		return nil
	}

	if val, ok := userHeaders[object.AttributeTimestamp]; ok {
		if dt, err := strconv.ParseInt(val, 10, 64); err == nil {
			creation = time.Unix(dt, 0)
		}
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
		UploadID: userHeaders[UploadIDAttributeName],
		Owner:    *meta.OwnerID(),
		Created:  creation,
	}
}

func appendUploadHeaders(metadata map[string]string, uploadID, key string, partNumber int) {
	metadata[UploadIDAttributeName] = uploadID
	metadata[UploadPartNumberAttributeName] = strconv.Itoa(partNumber)
	metadata[UploadKeyAttributeName] = key
}
