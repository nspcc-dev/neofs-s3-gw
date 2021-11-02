package handler

import (
	"encoding/xml"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
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

	uploadID := uuid.New()
	p := &layer.UploadPartParams{
		UploadID:   uploadID.String(),
		PartNumber: 0,
		Key:        reqInfo.ObjectName,
		Bkt:        bktInfo,
	}

	 _, err = h.obj.UploadPart(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not initiate multipart upload", reqInfo, err)
	}

	res := InitiateMultipartUploadResponse {
		Bucket:   bktInfo.Name,
		Key:      reqInfo.ObjectName,
		UploadID: uploadID.String(),
	}

	if err := api.EncodeToResponse(w, res); err != nil {
		h.logAndSendError(w, "could not encode InitiateMultipartUploadResponse to response ", reqInfo, err)
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
	if err != nil {
		h.logAndSendError(w, "invalid part number", reqInfo, err)
	}

	p := &layer.UploadPartParams{
		UploadID: queryValues.Get(uploadIdHeaderName),
		PartNumber: partNum,
		Key:        reqInfo.ObjectName,
		Bkt:        bktInfo,
		Reader:     r.Body,
		Size:       r.ContentLength,
	}

	info, err := h.obj.UploadPart(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not upload part", reqInfo, err)
		return
	}

	w.Header().Set(api.ETag, info.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func (h* handler) UploadPartCopy(w http.ResponseWriter, t *http.Request) {

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
	p := &layer.CompleteMultipartParams{
		Bkt:      bktInfo,
		Key:      reqInfo.ObjectName,
		UploadID: r.URL.Query().Get(uploadIdHeaderName),
	}
	info, err := h.obj.CompleteMultipartUpload(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not complete multipart upload", reqInfo, err)
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

// ListMultipartUploadsHandler implements multipart uploads listing handler.
func (h *handler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
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

	queryValues := reqInfo.URL.Query()

	var maxKeys int
	delimiter := queryValues.Get("delimiter")
	prefix := queryValues.Get("prefix")
	if queryValues.Get("max-keys") == "" {
		maxKeys = 1000
	} else if maxKeys, err = strconv.Atoi(queryValues.Get("max-keys")); err != nil || maxKeys < 0 {
		h.logAndSendError(w, "invalid maxKeys", reqInfo, err) //TODO IF ERR == NIL?
		return
	}

	p := &layer.ListMultipartUploadsParams{
		Bkt:           bktInfo,
		Delimiter:     delimiter,
		Prefix:        prefix,
		StartingToken: "",
		MaxItems:      0,
	}


	list, err := h.obj.ListMultipartUploads(r.Context(), p)


}
