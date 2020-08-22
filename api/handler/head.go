package handler

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}

	w.WriteHeader(http.StatusOK)

	w.Header().Set("Content-Type", inf.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(inf.Size, 10))

	w.Header().Set("Last-Modified", inf.Created.Format(http.TimeFormat))

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

		code := http.StatusBadRequest
		if st, ok := status.FromError(err); ok && st != nil {
			switch st.Code() {
			case codes.NotFound:
				code = http.StatusNotFound
			case codes.PermissionDenied:
				code = http.StatusForbidden
			}
		}

		api.WriteResponse(w, code, nil, api.MimeNone)

		return
	}

	api.WriteResponse(w, http.StatusOK, nil, api.MimeNone)
}
