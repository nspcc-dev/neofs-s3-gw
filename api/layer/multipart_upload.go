package layer

import (
	"context"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
	"io"
	"strconv"
	"time"
)

const (
	UploadIdAttributeName   = "S3-Upload-Id"
	PartNumberAttributeName = "S3-Upload-Part-Number"
	UploadKeyAttributeName = "S3-Upload-Key"
	UploadPartKeyPrefix = ".upload-"

	UploadMinSize  = 5 * 1048576
)

type (
	CompleteMultipartParams struct {
		Bkt      *data.BucketInfo
		Key      string
		UploadID string
		Parts []*Part
	}

	Part struct {
		ETag string
		PartNum int
		LastModified string
		Size int64
	}

	UploadPartParams struct {
		UploadID string
		PartNumber int
		Bkt *data.BucketInfo
		Key string
		Size int64
		Reader io.Reader
		Header map[string]string
	}

	AbortMultipartUploadParams struct {
		UploadID string
		Key string
		Bkt *data.BucketInfo
	}

	ListMultipartUploadsParams struct {
		Bkt *data.BucketInfo
		Delimiter string
		Prefix string
		StartingToken string
		MaxItems int
	}

	ListPartsParams struct {
		Bkt *data.BucketInfo
		UploadID string
		Key string
		MaxParts int
		PartNumberMarker int
	}
	ListPartsInfo struct {
		Parts []*Part
		Owner *owner.ID
		
	}
)

func (n *layer) UploadPart(ctx context.Context, p *UploadPartParams) (*data.ObjectInfo, error) {
	if p.PartNumber != 0 {
		_, err := n.getUploadParts(ctx, p.UploadID, p.Key, p.Bkt)
		if err != nil {
			return nil, err
		}
	}

	p.Header[UploadIdAttributeName] = p.UploadID
	p.Header[PartNumberAttributeName] = strconv.Itoa(p.PartNumber)
	p.Header[UploadKeyAttributeName] = p.Key

	params := &PutObjectParams{
		Bucket: p.Bkt.Name,
		Object: createUploadPartName(p.Key, p.PartNumber),
		Size:   p.Size,
		Reader: p.Reader,
		Header: p.Header,
	}

	return n.objectPut(ctx, p.Bkt, params)
}

func (n *layer) CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*data.ObjectInfo, error) {
	objects, err := n.getUploadParts(ctx, p.UploadID, p.Key, p.Bkt)
	if err != nil {
		return nil, err
	}
	parts := make([]*data.ObjectInfo, 0, len(p.Parts))

	for i, part := range p.Parts {
		info, ok := objects[part.PartNum]
		if !ok || part.ETag != info.HashSum {
			return nil, errors.GetAPIError(errors.ErrInvalidPart)
		}
		if i != len(p.Parts) - 1 && info.Size <= UploadMinSize {
			return nil, errors.GetAPIError(errors.ErrEntityTooSmall)
		}
		parts = append(parts, info)
	}

	initMetadata := objects[0].Headers


	pr, pw := io.Pipe()

	var obj *data.ObjectInfo
	done := make(chan bool)

	success := false


	delete(initMetadata, UploadIdAttributeName)
	delete(initMetadata, PartNumberAttributeName)
	delete(initMetadata, UploadKeyAttributeName)

	go func(done chan bool) {
		obj, err = n.objectPut(ctx, p.Bkt, &PutObjectParams{
			Bucket: p.Bkt.Name,
			Object: p.Key,
			Reader: pr,
			Header: initMetadata,
		})
		if err != nil {
			done <- true
			return
		}
		success = true
		done <- true
	}(done)

	for _, part := range parts {
		_, err := n.objectGetWithPayloadWriter(ctx, &getParams{
			Writer: pw,
			cid:    p.Bkt.CID,
			oid:    part.ID,
		})
		if err != nil {
			n.log.Error("could not download a part of multipart upload",
				zap.String("uploadID", p.UploadID),
				zap.String("part number", part.Headers[PartNumberAttributeName]),
				zap.Error(err))
			return nil, err
		}
	}

	pw.Close()
	<- done

	if success {
		t := &PutTaggingParams{
			ObjectInfo: obj,
			TagSet:     tags,
		}
		err := n.PutObjectTagging(ctx, t)
		if err != nil {

		}
		for _, objInfo := range parts {
			if err = n.objectDelete(ctx, p.Bkt.CID, objInfo.ID); err != nil {
				n.log.Warn("could not delete upload part",
					zap.Stringer("object id", objInfo.ID),
					zap.Stringer("bucket id", p.Bkt.CID),
					zap.Error(err))
			}
		}
	} else {
		err = n.objectDelete(ctx, obj.CID, obj.ID)
		if err != nil {
			n.log.Warn("could not delete incomplete object",
				zap.Error(err))
		}
		return nil, errors.GetAPIError(errors.ErrInternalError)
	}

	return obj, nil
}

func (n *layer) ListMultipartUploads(ctx context.Context, p *ListMultipartUploadsParams) ([]*data.ObjectInfo, error) {
	f := &findParams {
		attr:   UploadIdAttributeName,
		val:    "0",
		cid:    p.Bkt.CID,
		prefix: p.Prefix,
	}

	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}

	res := make([]*data.ObjectInfo, 0, len(ids))

	for _, id := range ids {
		meta, err := n.objectHead(ctx, p.Bkt.CID, id)
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", p.Bkt.CID),
				zap.Error(err))
			continue
		}
		info := objectInfoFromMeta(p.Bkt, meta, p.Prefix, p.Delimiter)

		res = append(res, info)
	}

	return res, nil
}

func (n *layer) AbortMultipartUpload(ctx context.Context, p *AbortMultipartUploadParams) error {
	objects, err := n.getUploadParts(ctx, p.UploadID, p.Key, p.Bkt)
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

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) ([]*Part, error) {
	objs, err := n.getUploadParts(ctx, p.UploadID, p.Key, p.Bkt)

	parts := make([]*Part, 0, len(objs))

	for _, obj := range objs {
		num, _ := strconv.Atoi(obj.Headers[PartNumberAttributeName]) // todo err??

		part := &Part{
			ETag:         obj.HashSum,
			PartNum:      num,
			LastModified: obj.Created.Format(time.RFC3339),
			Size:         obj.Size,
		}
	}

	f := &findParams {
		attr:   UploadIdAttributeName,
		val:    p.UploadID,
		cid:    p.Bkt.CID,
		prefix: "",
	}

	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}
	res := make([]*data.ObjectInfo, 0, len(ids))

	for _, id := range ids {
		meta, err := n.objectHead(ctx, p.Bkt.CID, id)
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", p.Bkt.CID),
				zap.Error(err))
			continue
		}
		info := objInfoFromMeta(p.Bkt, meta)

		res = append(res, info)
	}

	return res, nil
}

func (n* layer) getUploadParts(ctx context.Context, uploadID, key string, bktInfo *data.BucketInfo) (map[int]*data.ObjectInfo, error) {
	f := &findParams {
		attr:   UploadIdAttributeName,
		val:    uploadID,
		cid:    bktInfo.CID,
		prefix: "",
	}

	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchKey) {
			return nil, errors.GetAPIError(errors.ErrNoSuchUpload)
		} else {
			return nil, err
		}
	}

	res :=  make(map[int]*data.ObjectInfo)

	for _, id := range ids {
		meta, err := n.objectHead(ctx, bktInfo.CID, id)
		if err != nil {
			n.log.Warn("couldn't head a part of upload",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", bktInfo.CID),
				zap.Error(err))
			continue
		}
		attrs := userHeaders(meta.Attributes())
		if attrs[object.AttributeFileName] == key {
			num, err := strconv.Atoi(attrs[PartNumberAttributeName])
			if err != nil {
				n.log.Warn("could not cast part number",
					zap.Stringer("object id", id),
					zap.Stringer("bucket id", bktInfo.CID),
					zap.Error(err))
				continue
			}
			res[num] =  objInfoFromMeta(bktInfo, meta)
		}
	}

	if len(res) == 0 {
		return nil, errors.GetAPIError(errors.ErrNoSuchUpload)
	}

	return  res, nil
}

func createUploadPartName(key string, partNumber int ) string {
	return UploadPartKeyPrefix + key + strconv.Itoa(partNumber)
}