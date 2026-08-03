package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

type conditionalArgs struct {
	IfModifiedSince   *time.Time
	IfUnmodifiedSince *time.Time
	IfMatch           string
	IfNoneMatch       string
}

func fetchRangeHeader(headers http.Header) (layer.PayloadRange, error) {
	const prefix = "bytes="
	rangeHeader := headers.Get("Range")
	if len(rangeHeader) == 0 {
		return layer.PayloadRange{}, nil
	}
	if !strings.HasPrefix(rangeHeader, prefix) {
		return layer.PayloadRange{}, fmt.Errorf("unknown unit in range header")
	}
	arr := strings.Split(strings.TrimPrefix(rangeHeader, prefix), "-")
	if len(arr) != 2 || (len(arr[0]) == 0 && len(arr[1]) == 0) {
		return layer.PayloadRange{}, fmt.Errorf("unknown byte-range-set")
	}

	base, bitSize := 10, 64

	// "bytes=-N".
	if len(arr[0]) == 0 {
		ln, err := strconv.ParseUint(arr[1], base, bitSize)
		if err != nil || ln == 0 {
			return layer.PayloadRange{}, s3errors.GetAPIError(s3errors.ErrInvalidRange)
		}

		return layer.NewPayloadRangeSuffix(ln), nil
	}

	start, err := strconv.ParseUint(arr[0], base, bitSize)
	if err != nil {
		return layer.PayloadRange{}, s3errors.GetAPIError(s3errors.ErrInvalidRange)
	}

	// "bytes=N-".
	if len(arr[1]) == 0 {
		return layer.NewPayloadRangeFrom(start), nil
	}

	// "bytes=N-M".
	end, err := strconv.ParseUint(arr[1], base, bitSize)
	if err != nil || start > end {
		return layer.PayloadRange{}, s3errors.GetAPIError(s3errors.ErrInvalidRange)
	}

	return layer.NewPayloadRangeBounds(start, end), nil
}

func resolveRangeParams(rng layer.PayloadRange, fullSize uint64) (*layer.RangeParams, error) {
	if !rng.IsSet() {
		return nil, nil
	}

	off, ln, err := rng.Resolve(fullSize)
	if err != nil || ln == 0 {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidRange)
	}

	return &layer.RangeParams{Start: off, End: off + ln - 1}, nil
}

func overrideResponseHeaders(h http.Header, query url.Values) {
	for key, value := range query {
		if hdr, ok := api.ResponseModifiers[strings.ToLower(key)]; ok {
			h[hdr] = value
		}
	}
}

func addSSECHeaders(responseHeader http.Header, requestHeader http.Header) {
	responseHeader.Set(api.AmzServerSideEncryptionCustomerAlgorithm, requestHeader.Get(api.AmzServerSideEncryptionCustomerAlgorithm))
	responseHeader.Set(api.AmzServerSideEncryptionCustomerKeyMD5, requestHeader.Get(api.AmzServerSideEncryptionCustomerKeyMD5))
}

func writeHeaders(h http.Header, requestHeader http.Header, info *data.ObjectInfo, tagSetLength int, isBucketUnversioned bool) {
	if len(info.ContentType) > 0 && h.Get(api.ContentType) == "" {
		h.Set(api.ContentType, info.ContentType)
	}
	h.Set(api.LastModified, info.Created.UTC().Format(http.TimeFormat))

	if info.EncryptionMeta != nil {
		h.Set(api.ContentLength, strconv.FormatInt(info.EncryptionMeta.DecryptedSize, 10))
		addSSECHeaders(h, requestHeader)
	} else {
		h.Set(api.ContentLength, strconv.FormatInt(info.Size, 10))
	}

	h.Set(api.ETag, info.HashSum)
	h.Set(api.AmzTaggingCount, strconv.Itoa(tagSetLength))

	if !isBucketUnversioned {
		h.Set(api.AmzVersionID, info.Version)
	}

	if cacheControl := info.Headers[api.CacheControl]; cacheControl != "" {
		h.Set(api.CacheControl, cacheControl)
	}
	if expires := info.Headers[api.Expires]; expires != "" {
		h.Set(api.Expires, expires)
	}

	for key, val := range info.Headers {
		if layer.IsSystemHeader(key) {
			continue
		}
		h[api.MetadataPrefix+key] = []string{val}
	}
}

func (h *handler) readObject(ctx context.Context, bktInfo *data.BucketInfo, id oid.ID, rng layer.PayloadRange, headerOnly bool) (*data.ObjectInfo, layer.PayloadReadCloser, error) {
	if headerOnly {
		info, err := h.obj.GetObjectInfoByID(ctx, bktInfo, id)

		return info, nil, err
	}

	res, err := h.obj.GetObjectWithPayloadReader(ctx, &layer.GetObjectWithPayloadReaderParams{
		Owner:   bktInfo.Owner,
		BktInfo: bktInfo,
		Object:  id,
		Range:   rng,
	})
	if err != nil {
		return nil, nil, err
	}

	return res.ObjectInfo, res.Payload, nil
}

func (h *handler) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		payload layer.PayloadReadCloser

		reqInfo = api.GetReqInfo(r.Context())
	)

	conditional, err := parseConditionalHeaders(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse request params", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	encryptionParams, err := formEncryptionParams(r)
	if err != nil {
		h.logAndSendError(w, "invalid sse headers", reqInfo, err)
		return
	}

	rng, err := fetchRangeHeader(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse range header", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:                   bktInfo,
		Object:                    reqInfo.ObjectName,
		VersionID:                 reqInfo.URL.Query().Get(api.QueryVersionID),
		IsBucketVersioningEnabled: bktInfo.Settings.VersioningEnabled(),
	}

	comprehensiveObjectInfo, err := h.obj.ComprehensiveObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	var (
		headerOnly    = encryptionParams.Enabled()
		partNumberStr = reqInfo.URL.Query().Get("partNumber")
	)

	info, payload, err := h.readObject(r.Context(), bktInfo, comprehensiveObjectInfo.ID, rng, headerOnly || len(partNumberStr) > 0)
	if err != nil {
		h.logAndSendError(w, "could not get object meta", reqInfo, err)
		return
	}

	// Closes the stream if it wasn't passed to the client below.
	defer func() {
		if payload != nil {
			_ = payload.Close()
		}
	}()

	// There are no tags in separate objects. Try to get tags from the object headers.
	if len(comprehensiveObjectInfo.TagSet) == 0 {
		for k, v := range info.Headers {
			if after, ok := strings.CutPrefix(k, s3headers.NeoFSSystemMetadataTagPrefix); ok {
				comprehensiveObjectInfo.TagSet[after] = v
			}
		}
	}

	if err = checkPreconditions(info, conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, err)
		return
	}

	if err = encryptionParams.MatchObjectEncryption(layer.FormEncryptionInfoFromMeta(info.EncryptionMeta)); err != nil {
		h.logAndSendError(w, "encryption doesn't match object", reqInfo, s3errors.GetAPIError(s3errors.ErrBadRequest), zap.Error(err))
		return
	}

	var pInfo *layer.Part
	if len(partNumberStr) > 0 {
		var partNumber int

		partNumber, err = strconv.Atoi(partNumberStr)
		if err != nil || partNumber < layer.UploadMinPartNumber || partNumber > layer.UploadMaxPartNumber {
			h.logAndSendError(w, "invalid part number", reqInfo, s3errors.GetAPIError(s3errors.ErrInvalidPartNumber))
			return
		}

		completedParts, _, err := h.obj.GetMultipartParts(r.Context(), bktInfo, info.ID)
		if err != nil {
			h.logAndSendError(w, "linking object, get multipart parts", reqInfo, s3errors.GetAPIError(s3errors.ErrInternalError))
			return
		}

		var totalParts = len(completedParts)
		if partNumber > totalParts {
			h.logAndSendError(w, "requested part not found", reqInfo, s3errors.GetAPIError(s3errors.ErrInvalidPartNumber))
			return
		}

		part := completedParts[partNumber-1]

		info, payload, err = h.readObject(r.Context(), bktInfo, part.ObjectID(), rng, headerOnly)
		if err != nil {
			h.logAndSendError(w, "could not get part object meta", reqInfo, err)
			return
		}

		w.Header().Set("x-amz-mp-parts-count", strconv.Itoa(totalParts))
	}

	fullSize := info.Size
	if encryptionParams.Enabled() && info.EncryptionMeta != nil {
		fullSize = info.EncryptionMeta.DecryptedSize
	}

	// The range has been resolved by NeoFS, but we need it for the response as well.
	params, err := resolveRangeParams(rng, uint64(fullSize))
	if err != nil {
		h.logAndSendError(w, "could not resolve range header", reqInfo, err)
		return
	}

	if layer.IsAuthenticatedRequest(r.Context()) {
		overrideResponseHeaders(w.Header(), reqInfo.URL.Query())
	}

	if err = h.setLockingHeaders(bktInfo, comprehensiveObjectInfo.LockInfo, w.Header()); err != nil {
		h.logAndSendError(w, "could not get locking info", reqInfo, err)
		return
	}

	writeHeaders(w.Header(), r.Header, info, len(comprehensiveObjectInfo.TagSet), bktInfo.Settings.Unversioned())
	if params != nil {
		writeRangeHeaders(w, params, info.Size)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if payload == nil {
		getParams := &layer.GetObjectParams{
			ObjectInfo: info,
			Writer:     w,
			Range:      params,
			BucketInfo: bktInfo,
			Encryption: encryptionParams,
			Part:       pInfo,
		}
		if err = h.obj.GetObject(r.Context(), getParams); err != nil {
			h.logAndSendError(w, "could not get object", reqInfo, err)
		}

		return
	}

	if _, err = payload.WriteTo(w); err != nil {
		h.logAndSendError(w, "could write object output", reqInfo, err)
	}

	if err = payload.Close(); err != nil {
		h.logAndSendError(w, "close output", reqInfo, err)
	}

	payload = nil
}

func checkPreconditions(info *data.ObjectInfo, args *conditionalArgs) error {
	if len(args.IfMatch) > 0 && args.IfMatch != info.HashSum {
		return s3errors.GetAPIError(s3errors.ErrPreconditionFailed)
	}
	if len(args.IfNoneMatch) > 0 && args.IfNoneMatch == info.HashSum {
		return s3errors.GetAPIError(s3errors.ErrNotModified)
	}
	if args.IfModifiedSince != nil && info.Created.Before(*args.IfModifiedSince) {
		return s3errors.GetAPIError(s3errors.ErrNotModified)
	}
	if args.IfUnmodifiedSince != nil && info.Created.After(*args.IfUnmodifiedSince) {
		if len(args.IfMatch) == 0 {
			return s3errors.GetAPIError(s3errors.ErrPreconditionFailed)
		}
	}

	return nil
}

func parseConditionalHeaders(headers http.Header) (*conditionalArgs, error) {
	var err error
	args := &conditionalArgs{
		IfMatch:     headers.Get(api.IfMatch),
		IfNoneMatch: headers.Get(api.IfNoneMatch),
	}

	if args.IfModifiedSince, err = parseHTTPTime(headers.Get(api.IfModifiedSince)); err != nil {
		return nil, err
	}
	if args.IfUnmodifiedSince, err = parseHTTPTime(headers.Get(api.IfUnmodifiedSince)); err != nil {
		return nil, err
	}

	return args, nil
}

func parseHTTPTime(data string) (*time.Time, error) {
	if len(data) == 0 {
		return nil, nil
	}

	result, err := time.Parse(http.TimeFormat, data)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse http time %s: %w", data, err)
	}
	return &result, nil
}

func writeRangeHeaders(w http.ResponseWriter, params *layer.RangeParams, size int64) {
	w.Header().Set(api.AcceptRanges, "bytes")
	w.Header().Set(api.ContentRange, fmt.Sprintf("bytes %d-%d/%d", params.Start, params.End, size))
	w.Header().Set(api.ContentLength, strconv.FormatUint(params.End-params.Start+1, 10))
	w.WriteHeader(http.StatusPartialContent)
}
