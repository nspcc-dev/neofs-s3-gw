package handler

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

type copyObjectArgs struct {
	Conditional       *conditionalArgs
	MetadataDirective string
}

const replaceMetadataDirective = "REPLACE"

// path2BucketObject returns a bucket and an object.
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
		info     *data.ObjectInfo
		metadata map[string]string

		reqInfo   = api.GetReqInfo(r.Context())
		versionID string
	)

	src := r.Header.Get("X-Amz-Copy-Source")
	// Check https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html
	// Regardless of whether you have enabled versioning, each object in your bucket
	// has a version ID. If you have not enabled versioning, Amazon S3 sets the value
	// of the version ID to null. If you have enabled versioning, Amazon S3 assigns a
	// unique version ID value for the object.
	if u, err := url.Parse(src); err == nil {
		versionID = u.Query().Get(api.QueryVersionID)
		src = u.Path
	}

	srcBucket, srcObject := path2BucketObject(src)

	args, err := parseCopyObjectArgs(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse request params", reqInfo, err)
		return
	}
	p := &layer.HeadObjectParams{
		Object:    srcObject,
		VersionID: versionID,
	}

	if args.MetadataDirective == replaceMetadataDirective {
		metadata = parseMetadata(r)
	} else if srcBucket == reqInfo.BucketName && srcObject == reqInfo.ObjectName {
		h.logAndSendError(w, "could not copy to itself", reqInfo, errors.GetAPIError(errors.ErrInvalidRequest))
		return
	}

	if p.BktInfo, err = h.getBucketAndCheckOwner(r, srcBucket, api.AmzSourceExpectedBucketOwner); err != nil {
		h.logAndSendError(w, "couldn't get source bucket", reqInfo, err)
		return
	}

	dstBktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "couldn't get target bucket", reqInfo, err)
		return
	}

	if info, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	if err = checkPreconditions(info, args.Conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, errors.GetAPIError(errors.ErrPreconditionFailed))
		return
	}

	if metadata == nil {
		if len(info.ContentType) > 0 {
			info.Headers[api.ContentType] = info.ContentType
		}
		metadata = info.Headers
	} else if contentType := r.Header.Get(api.ContentType); len(contentType) > 0 {
		metadata[api.ContentType] = contentType
	}

	params := &layer.CopyObjectParams{
		SrcObject:  info,
		DstBktInfo: dstBktInfo,
		DstObject:  reqInfo.ObjectName,
		SrcSize:    info.Size,
		Header:     metadata,
	}

	settings, err := h.obj.GetBucketSettings(r.Context(), dstBktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
		return
	}

	params.Lock, err = formObjectLock(dstBktInfo, settings.LockConfiguration, r.Header)
	if err != nil {
		h.logAndSendError(w, "could not form object lock", reqInfo, err)
		return
	}

	additional := []zap.Field{zap.String("src_bucket_name", srcBucket), zap.String("src_object_name", srcObject)}
	if info, err = h.obj.CopyObject(r.Context(), params); err != nil {
		h.logAndSendError(w, "couldn't copy object", reqInfo, err, additional...)
		return
	} else if err = api.EncodeToResponse(w, &CopyObjectResponse{LastModified: info.Created.UTC().Format(time.RFC3339), ETag: info.HashSum}); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err, additional...)
		return
	}

	h.log.Info("object is copied",
		zap.String("bucket", info.Bucket),
		zap.String("object", info.Name),
		zap.Stringer("object_id", info.ID))

	s := &SendNotificationParams{
		Event:   EventObjectCreatedCopy,
		ObjInfo: info,
		BktInfo: dstBktInfo,
		ReqInfo: reqInfo,
	}
	if err = h.sendNotifications(r.Context(), s); err != nil {
		h.log.Error("couldn't send notification: %w", zap.Error(err))
	}
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
