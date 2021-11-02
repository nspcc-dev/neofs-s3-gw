package layer

import (
	"context"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
	"io"
	"sort"
	"strconv"
)

const (
	UploadIdAttributeName   = "S3-Upload-Id"
	PartNumberAttributeName = "S3-Upload-Part-Number"
	UploadPartKeyPrefix = ".upload-"
)

type (
	CompleteMultipartParams struct {
		Bkt      *data.BucketInfo
		Key      string
		UploadID string
	}

	UploadPartParams struct {
		UploadID string
		PartNumber int
		Key string
		Bkt *data.BucketInfo
		Reader io.Reader
		Size int64
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
)

func (n *layer) UploadPart(ctx context.Context, p *UploadPartParams) (*data.ObjectInfo, error) {
	f := &findParams{
		attr:   UploadIdAttributeName,
		val:    p.UploadID,
		cid:    p.Bkt.CID,
		prefix: "",
	}

	_, err := n.objectSearch(ctx, f)
	if err != nil && errors.IsS3Error(err, errors.ErrNoSuchKey){
		return nil, errors.GetAPIError(errors.ErrNoSuchUpload)
	}
	
	metadata := make(map[string]string)

	metadata[UploadIdAttributeName] = p.UploadID
	metadata[PartNumberAttributeName] = strconv.Itoa(p.PartNumber)

	params := &PutObjectParams {
		Bucket: p.Bkt.Name,
		Object: createUploadPartName(p.Key, p.PartNumber),
		Reader: p.Reader,
		Size:   p.Size,
		Header: metadata,
	}

	return n.objectPut(ctx, p.Bkt, params)
}


func createUploadPartName(key string, partNumber int ) string {
	return UploadPartKeyPrefix + key + strconv.Itoa(partNumber)
}

func (n *layer) CompleteMultipartUpload(ctx context.Context, p *CompleteMultipartParams) (*data.ObjectInfo, error) {
	f := &findParams{
		attr:   UploadIdAttributeName,
		val:    p.UploadID,
		cid:    p.Bkt.CID,
		prefix: "",
	}
	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}

	order := make(map[int]*data.ObjectInfo)
	partNumbers := make([]int, 0)

	for _, id := range ids {
		meta, err := n.objectHead(ctx, p.Bkt.CID, id)
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", id),
				zap.Stringer("bucket id", p.Bkt.CID),
				zap.Error(err))
			return nil, err // TODO add specific error in this case
		}
		attrs := userHeaders(meta.Attributes())
		numStr := attrs[PartNumberAttributeName]
		num, err := strconv.Atoi(numStr)
		if err != nil {
			continue // ???
		}
		order[num] = objInfoFromMeta(p.Bkt, meta)
		partNumbers = append(partNumbers, num)
	}
	sort.Ints(partNumbers)

	pr, pw := io.Pipe()


	var obj *data.ObjectInfo
	done := make(chan bool)

	go func(done chan bool) {
		obj, err = n.objectPut(ctx, p.Bkt, &PutObjectParams{
			Bucket: p.Bkt.Name,
			Object: p.Key,
			Reader: pr,
			Header: make(map[string]string),
		})
		if err != nil {
			done <- true
			return
		}
		for _, objInfo := range order {
			if err = n.objectDelete(ctx, p.Bkt.CID, objInfo.ID); err != nil {
				n.log.Warn("could not delete upload part")
			}
		}
		done <- true
	}(done)

	for _, num := range partNumbers {
		if num == 0 {
			continue
		}
		_, err := n.objectGetWithPayloadWriter(ctx, &getParams{
			Writer: pw,
			cid:    p.Bkt.CID,
			oid:    order[num].ID,
		})
		if err != nil {
			n.log.Error("no object " + strconv.Itoa(num) + " why " +  err.Error())
			continue
		}
	}
	pw.Close()
	<- done
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
	f := &findParams {
		attr:   UploadIdAttributeName,
		val:    p.UploadID,
		cid:    p.Bkt.CID,
		prefix: "",
	}
	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return err
	}

	for _, id := range ids {
		err := n.objectDelete(ctx, p.Bkt.CID, id)
		if err != nil {
			return err
		}
	}

	return nil
}

func (n *layer) ListParts(ctx context.Context, p *ListPartsParams) ([]*data.ObjectInfo, error) {
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