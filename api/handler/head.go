package handler

import (
	"bytes"
	"net/http"

	"github.com/gorilla/mux"
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

		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	if inf, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err != nil {
		h.log.Error("could not fetch object info",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, err, r.URL)
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
		h.log.Error("could not get object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Stringer("oid", inf.ID()),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, err, r.URL)

		return
	}
	inf.ContentType = http.DetectContentType(buffer.Bytes())
	writeHeaders(w.Header(), inf)
	w.WriteHeader(http.StatusOK)
}

func (h *handler) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	var (
		req = mux.Vars(r)
		bkt = req["bucket"]
		rid = api.GetRequestID(r.Context())
	)

	if _, err := h.obj.GetBucketInfo(r.Context(), bkt); err != nil {
		h.log.Error("could not fetch object info",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, err, r.URL)
		return
	}

	api.WriteResponse(w, http.StatusOK, nil, api.MimeNone)
}
