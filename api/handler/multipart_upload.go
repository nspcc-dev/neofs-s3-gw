package handler

import (
	"encoding/xml"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"go.uber.org/zap"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

type (
	InitiateMultipartUploadResponse struct {
		XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult" json:"-"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}
	CompleteMultipartUploadResponse struct {
		XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult" json:"-"`
		Bucket string `xml:"Bucket"`
		Key string `xml:"Key"`
		ETag string `xml:"ETag"`
	}
)

const (
	uploadIdHeaderName   = "uploadId"
	partNumberHeaderName = "partNumber"
)

func (h *handler) CreateMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err := checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	metadata := parseMetadata(r)
	if contentType := r.Header.Get(api.ContentType); len(contentType) > 0 {
		metadata[api.ContentType] = contentType
	}

	uploadID := uuid.New()

	p := &layer.UploadPartParams{
		UploadID:   uploadID.String(),
		PartNumber: 0,
		Bkt:        bktInfo,
		Key:        reqInfo.ObjectName,
		Header:     metadata,
	}

	info, err := h.obj.UploadPart(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not upload a part",reqInfo, err)
	}

	var newEaclTable *eacl.Table
	if containsACLHeaders(r) {
		if newEaclTable, err = h.getNewEAclTable(r, info); err != nil {
			h.logAndSendError(w, "could not get new eacl table", reqInfo, err)
			return
		}
	}
	if newEaclTable != nil {
		p := &layer.PutBucketACLParams{
			Name: reqInfo.BucketName,
			EACL: newEaclTable,
		}

		if err = h.obj.PutBucketACL(r.Context(), p); err != nil {
			h.logAndSendError(w, "could not put bucket acl", reqInfo, err)
			return
		}
	}

	tagSet, err := parseTaggingHeader(r.Header)
	if tagSet != nil {
		if err = h.obj.PutObjectTagging(r.Context(), &layer.PutTaggingParams{ObjectInfo: info, TagSet: tagSet}); err != nil {
			h.logAndSendError(w, "could not upload object tagging", reqInfo, err)
			return
		}
	}

	resp := InitiateMultipartUploadResponse {
		Bucket:   bktInfo.Name,
		Key:      reqInfo.ObjectName,
		UploadID: uploadID.String(),
	}

	if err := api.EncodeToResponse(w, resp); err != nil {
		h.logAndSendError(w, "could not encode InitiateMultipartUploadResponse to response", reqInfo, err)
		return
	}
}

func (h *handler) UploadPartHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err := checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	queryValues := r.URL.Query()

	partNum, err := strconv.Atoi(queryValues.Get(partNumberHeaderName))
	if err != nil || partNum == 0 {
		h.logAndSendError(w, "invalid part number", reqInfo, err)
		return
	}

	p := &layer.UploadPartParams{
		UploadID:   queryValues.Get(uploadIdHeaderName),
		PartNumber: partNum,
		Bkt:        bktInfo,
		Key:        reqInfo.ObjectName,
		Size:       r.ContentLength,
		Reader:     r.Body,
	}

	info, err := h.obj.UploadPart(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not upload part", reqInfo, err)
		return
	}

	w.Header().Set(api.ETag, info.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func (h *handler) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err := checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	h := &layer.HeadObjectParams{
		Bucket:    reqInfo.BucketName,
		Object:    reqInfo.ObjectName,
		VersionID: "",
	}

	objInfo := h.obj.GetObjectInfo(r.Context(), )

	tags, err := h.obj.GetObjectTagging(ctx, )
	if err != nil {
		n.log.Error("could not get tagging file of multipart upload",
			zap.String("uploadID", p.UploadID),
			zap.String("part number", initMetadata[PartNumberAttributeName]),
			zap.Error(err))
		return nil, err
	}

	p := &layer.CompleteMultipartParams{
		Bkt:      bktInfo,
		Key:      reqInfo.ObjectName,
		UploadID: r.URL.Query().Get(uploadIdHeaderName),
	}
	info, err := h.obj.CompleteMultipartUpload(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not complete multipart upload", reqInfo, err)
		return
	}

	res := &CompleteMultipartUploadResponse{
		Bucket:  info.Bucket,
		Key:     info.Name,
		ETag:    info.HashSum,
	}

	if err := api.EncodeToResponse(w, res); err != nil {
		h.logAndSendError(w, "could not encode InitiateMultipartUploadResponse to response ", reqInfo, err)
	}
}

//// ListMultipartUploadsHandler implements multipart uploads listing handler.
//func (h *handler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
//	reqInfo := api.GetReqInfo(r.Context())
//
//	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
//	if err != nil {
//		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
//		return
//	}
//
//	if err := checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
//		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
//		return
//	}
//
//	queryValues := reqInfo.URL.Query()
//
//	var maxKeys int
//	delimiter := queryValues.Get("delimiter")
//	prefix := queryValues.Get("prefix")
//	if queryValues.Get("max-keys") == "" {
//		maxKeys = 1000
//	} else if maxKeys, err = strconv.Atoi(queryValues.Get("max-keys")); err != nil || maxKeys < 0 {
//		h.logAndSendError(w, "invalid maxKeys", reqInfo, err) //TODO IF ERR == NIL?
//		return
//	}
//
//	p := &layer.ListMultipartUploadsParams{
//		Bkt:           bktInfo,
//		Delimiter:     delimiter,
//		Prefix:        prefix,
//		StartingToken: "",
//		MaxItems:      0,
//	}
//
//
//	list, err := h.obj.ListMultipartUploads(r.Context(), p)
//
//
//}


