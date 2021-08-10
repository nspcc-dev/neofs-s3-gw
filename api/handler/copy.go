package handler

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

type copyObjectArgs struct {
	Conditional       *conditionalArgs
	MetadataDirective string
}

const replaceMetadataDirective = "REPLACE"

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
		err      error
		inf      *layer.ObjectInfo
		metadata map[string]string

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
			h.logAndSendError(w, "no such version", reqInfo, errors.GetAPIError(errors.ErrNoSuchVersion))
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
	p := &layer.HeadObjectParams{
		Bucket:    srcBucket,
		Object:    srcObject,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	if args.MetadataDirective == replaceMetadataDirective {
		metadata = parseMetadata(r)
	} else if srcBucket == reqInfo.BucketName && srcObject == reqInfo.ObjectName {
		h.logAndSendError(w, "could not copy to itself", reqInfo, errors.GetAPIError(errors.ErrInvalidRequest))
		return
	}

	if err = h.checkBucketOwner(r, srcBucket, r.Header.Get(api.AmzSourceExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "source expected owner doesn't match", reqInfo, err)
		return
	}
	if err = h.checkBucketOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	if inf, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	if err = checkPreconditions(inf, args.Conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, errors.GetAPIError(errors.ErrPreconditionFailed))
		return
	}

	if metadata == nil {
		if len(inf.ContentType) > 0 {
			inf.Headers[api.ContentType] = inf.ContentType
		}
		metadata = inf.Headers
	} else if contentType := r.Header.Get(api.ContentType); len(contentType) > 0 {
		metadata[api.ContentType] = contentType
	}

	params := &layer.CopyObjectParams{
		SrcObject: inf,
		DstBucket: reqInfo.BucketName,
		DstObject: reqInfo.ObjectName,
		SrcSize:   inf.Size,
		Header:    metadata,
	}

	additional := []zap.Field{zap.String("src_bucket_name", srcBucket), zap.String("src_object_name", srcObject)}
	if inf, err = h.obj.CopyObject(r.Context(), params); err != nil {
		h.logAndSendError(w, "couldn't copy object", reqInfo, err, additional...)
		return
	} else if err = api.EncodeToResponse(w, &CopyObjectResponse{LastModified: inf.Created.Format(time.RFC3339), ETag: inf.HashSum}); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err, additional...)
		return
	}

	h.log.Info("object is copied",
		zap.String("bucket", inf.Bucket),
		zap.String("object", inf.Name),
		zap.Stringer("object_id", inf.ID()))
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

	copyArgs := &copyObjectArgs{Conditional: args}
	copyArgs.MetadataDirective = headers.Get(api.AmzMetadataDirective)

	return copyArgs, nil
}
