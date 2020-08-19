package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"go.uber.org/zap"
)

func (h *handler) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	if _, err := h.obj.GetBucketInfo(r.Context(), bkt); err != nil {
		h.log.Error("could not find bucket",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrBadRequest).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)

		return
	} else if _, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err == nil {
		h.log.Error("object exists",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrMethodNotAllowed).Code,
			Description:    "Object: " + bkt + "#" + obj + " already exists",
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)

		return
	}

	params := &layer.PutObjectParams{
		Bucket: bkt,
		Object: obj,
		Reader: r.Body,
		Size:   r.ContentLength,
	}

	if _, err = h.obj.PutObject(r.Context(), params); err != nil {
		h.log.Error("could not upload object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}

	api.WriteSuccessResponseHeadersOnly(w)
}
