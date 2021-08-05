package handler

import (
	"bytes"
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

const sizeToDetectType = 512

func getRangeToDetectContentType(maxSize int64) *layer.RangeParams {
	end := uint64(maxSize)
	if sizeToDetectType < end {
		end = sizeToDetectType
	}

	return &layer.RangeParams{
		Start: 0,
		End:   end - 1,
	}
}

func (h *handler) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		inf *layer.ObjectInfo

		reqInfo = api.GetReqInfo(r.Context())
	)

	if inf, err = h.obj.GetObjectInfo(r.Context(), reqInfo.BucketName, reqInfo.ObjectName); err != nil {
		h.logAndSendError(w, "could not fetch object info", reqInfo, err)
		return
	}
	buffer := bytes.NewBuffer(make([]byte, 0, sizeToDetectType))
	getParams := &layer.GetObjectParams{
		Bucket: inf.Bucket,
		Object: inf.Name,
		Writer: buffer,
		Range:  getRangeToDetectContentType(inf.Size),
	}
	if err = h.obj.GetObject(r.Context(), getParams); err != nil {
		h.logAndSendError(w, "could not get object", reqInfo, err, zap.Stringer("oid", inf.ID()))
		return
	}
	inf.ContentType = http.DetectContentType(buffer.Bytes())
	writeHeaders(w.Header(), inf)
	w.WriteHeader(http.StatusOK)
}

func (h *handler) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	if _, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "could not fetch object info", reqInfo, err)
		return
	}

	api.WriteResponse(w, http.StatusOK, nil, api.MimeNone)
}
