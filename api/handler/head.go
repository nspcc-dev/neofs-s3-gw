package handler

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type devNull int

func (d devNull) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (h *handler) checkIsFolder(ctx context.Context, bucket, object string) *layer.ObjectInfo {
	if ln := len(object); ln > 0 && object[ln-1:] != layer.PathSeparator {
		return nil
	}

	_, dirname := layer.NameFromString(object)
	params := &layer.ListObjectsParams{Bucket: bucket, Prefix: dirname, Delimiter: layer.PathSeparator}

	if list, err := h.obj.ListObjects(ctx, params); err == nil && len(list.Objects) > 0 {
		return &layer.ObjectInfo{
			Bucket: bucket,
			Name:   object,

			ContentType: "text/directory",

			Owner:   list.Objects[0].Owner,
			Created: list.Objects[0].Created,
		}
	}

	return nil
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

	if inf = h.checkIsFolder(r.Context(), bkt, obj); inf != nil {
		// do nothing for folders

		// h.log.Debug("found folder",
		// 	zap.String("request_id", rid),
		// 	zap.String("bucket_name", bkt),
		// 	zap.String("object_name", obj))
	} else if inf, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err != nil {
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
	} else if inf.ContentType, err = h.contentTypeFetcher(r.Context(), devNull(0), inf); err != nil {
		h.log.Error("could not get object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Stringer("oid", inf.ID()),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}

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

		code := http.StatusBadRequest
		if st, ok := status.FromError(err); ok && st != nil {
			switch st.Code() { //nolint:exhaustive // we have default value set above
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
