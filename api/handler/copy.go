package handler

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"go.uber.org/zap"
)

// path2BucketObject returns bucket and object.
func path2BucketObject(path string) (bucket, prefix string) {
	path = strings.TrimPrefix(path, api.SlashSeparator)
	m := strings.Index(path, api.SlashSeparator)
	if m < 0 {
		return path, ""
	}
	return path[:m], path[m+len(api.SlashSeparator):]
}

func (h *handler) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		inf *layer.ObjectInfo

		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	src := r.Header.Get("X-Amz-Copy-Source")
	// Check https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html
	// Regardless of whether you have enabled versioning, each object in your bucket
	// has a version ID. If you have not enabled versioning, Amazon S3 sets the value
	// of the version ID to null. If you have enabled versioning, Amazon S3 assigns a
	// unique version ID value for the object.
	if u, err := url.Parse(src); err == nil {
		// Check if versionId query param was added, if yes then check if
		// its non "null" value, we should error out since we do not support
		// any versions other than "null".
		if vid := u.Query().Get("versionId"); vid != "" && vid != "null" {
			api.WriteErrorResponse(r.Context(), w, api.Error{
				Code:           api.GetAPIError(api.ErrNoSuchVersion).Code,
				Description:    "",
				HTTPStatusCode: http.StatusBadRequest,
			}, r.URL)
			return
		}

		src = u.Path
	}

	srcBucket, srcObject := path2BucketObject(src)

	params := &layer.CopyObjectParams{
		SrcBucket: srcBucket,
		DstBucket: bkt,
		SrcObject: srcObject,
		DstObject: obj,
	}

	if inf, err = h.obj.CopyObject(r.Context(), params); err != nil {
		h.log.Error("could not copy object",
			zap.String("request_id", rid),
			zap.String("dst_bucket_name", bkt),
			zap.String("dst_object_name", obj),
			zap.String("src_bucket_name", srcBucket),
			zap.String("src_object_name", srcObject),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	} else if err = api.EncodeToResponse(w, &CopyObjectResponse{LastModified: inf.Created.Format(time.RFC3339)}); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.String("dst_bucket_name", bkt),
			zap.String("dst_object_name", obj),
			zap.String("src_bucket_name", srcBucket),
			zap.String("src_object_name", srcObject),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}
