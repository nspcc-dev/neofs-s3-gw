package handler

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

type copyObjectArgs struct {
	Conditional *conditionalArgs
}

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

		reqInfo = api.GetReqInfo(r.Context())
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
			h.logAndSendError(w, "no such version", reqInfo, api.GetAPIError(api.ErrNoSuchVersion))
			return
		}

		src = u.Path
	}

	srcBucket, srcObject := path2BucketObject(src)

	args, err := parseCopyObjectArgs(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse request params", reqInfo, err)
		return
	}

	if inf, err = h.obj.GetObjectInfo(r.Context(), srcBucket, srcObject); err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	if err = checkPreconditions(inf, args.Conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, api.GetAPIError(api.ErrPreconditionFailed))
		return
	}

	params := &layer.CopyObjectParams{
		SrcBucket: srcBucket,
		DstBucket: reqInfo.BucketName,
		SrcObject: srcObject,
		DstObject: reqInfo.ObjectName,
		SrcSize:   inf.Size,
		Header:    inf.Headers,
	}

	if inf, err = h.obj.CopyObject(r.Context(), params); err != nil {
		writeErrorCopy(w, reqInfo, h.log, "could not copy object", srcBucket, srcObject, err)
		return
	} else if err = api.EncodeToResponse(w, &CopyObjectResponse{LastModified: inf.Created.Format(time.RFC3339), ETag: inf.HashSum}); err != nil {
		writeErrorCopy(w, reqInfo, h.log, "something went wrong", srcBucket, srcObject, err)
		return
	}

	h.log.Info("object is copied",
		zap.String("bucket", inf.Bucket),
		zap.String("object", inf.Name),
		zap.Stringer("object_id", inf.ID()))
}

func writeErrorCopy(w http.ResponseWriter, reqInfo *api.ReqInfo, log *zap.Logger, msg, srcBucket, srcObject string, err error) {
	log.Error(msg,
		zap.String("request_id", reqInfo.RequestID),
		zap.String("dst_bucket_name", reqInfo.BucketName),
		zap.String("dst_object_name", reqInfo.ObjectName),
		zap.String("src_bucket_name", srcBucket),
		zap.String("src_object_name", srcObject),
		zap.Error(err))

	api.WriteErrorResponse(w, reqInfo, err)
}

func parseCopyObjectArgs(headers http.Header) (*copyObjectArgs, error) {
	var err error
	args := &conditionalArgs{
		IfMatch:     headers.Get(api.AmzCopyIfMatch),
		IfNoneMatch: headers.Get(api.AmzCopyIfNoneMatch),
	}

	if args.IfModifiedSince, err = parseHTTPTime(headers.Get(api.AmzCopyIfModifiedSince)); err != nil {
		return nil, err
	}
	if args.IfUnmodifiedSince, err = parseHTTPTime(headers.Get(api.AmzCopyIfUnmodifiedSince)); err != nil {
		return nil, err
	}

	return &copyObjectArgs{Conditional: args}, nil
}
