package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"go.uber.org/zap"
)

func (h *handler) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	if err := h.obj.DeleteObject(r.Context(), bkt, obj); err != nil {
		h.log.Error("could not delete object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Error(err))

		// Ignore delete errors:

		// api.WriteErrorResponse(r.Context(), w, api.Error{
		// 	Code:           api.GetAPIError(api.ErrInternalError).Code,
		// 	Description:    err.Error(),
		// 	HTTPStatusCode: http.StatusInternalServerError,
		// }, r.URL)
	}

	w.WriteHeader(http.StatusNoContent)
}
