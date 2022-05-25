package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

type conditionalArgs struct {
	IfModifiedSince   *time.Time
	IfUnmodifiedSince *time.Time
	IfMatch           string
	IfNoneMatch       string
}

type getObjectArgs struct {
	Conditional *conditionalArgs
}

func fetchRangeHeader(headers http.Header, fullSize uint64) (*layer.RangeParams, error) {
	const prefix = "bytes="
	rangeHeader := headers.Get("Range")
	if len(rangeHeader) == 0 {
		return nil, nil
	}
	if fullSize == 0 {
		return nil, errors.GetAPIError(errors.ErrInvalidRange)
	}
	if !strings.HasPrefix(rangeHeader, prefix) {
		return nil, fmt.Errorf("unknown unit in range header")
	}
	arr := strings.Split(strings.TrimPrefix(rangeHeader, prefix), "-")
	if len(arr) != 2 || (len(arr[0]) == 0 && len(arr[1]) == 0) {
		return nil, fmt.Errorf("unknown byte-range-set")
	}

	var end, start uint64
	var err0, err1 error
	base, bitSize := 10, 64

	if len(arr[0]) == 0 {
		end, err1 = strconv.ParseUint(arr[1], base, bitSize)
		start = fullSize - end
		end = fullSize - 1
	} else if len(arr[1]) == 0 {
		start, err0 = strconv.ParseUint(arr[0], base, bitSize)
		end = fullSize - 1
	} else {
		start, err0 = strconv.ParseUint(arr[0], base, bitSize)
		end, err1 = strconv.ParseUint(arr[1], base, bitSize)
		if end > fullSize-1 {
			end = fullSize - 1
		}
	}

	if err0 != nil || err1 != nil || start > end || start > fullSize {
		return nil, errors.GetAPIError(errors.ErrInvalidRange)
	}
	return &layer.RangeParams{Start: start, End: end}, nil
}

func overrideResponseHeaders(h http.Header, query url.Values) {
	for key, value := range query {
		if hdr, ok := api.ResponseModifiers[strings.ToLower(key)]; ok {
			h[hdr] = value
		}
	}
}

func writeHeaders(h http.Header, info *data.ObjectInfo, tagSetLength int) {
	if len(info.ContentType) > 0 && h.Get(api.ContentType) == "" {
		h.Set(api.ContentType, info.ContentType)
	}
	h.Set(api.LastModified, info.Created.UTC().Format(http.TimeFormat))
	h.Set(api.ContentLength, strconv.FormatInt(info.Size, 10))
	h.Set(api.ETag, info.HashSum)
	h.Set(api.AmzVersionID, info.ID.EncodeToString())
	h.Set(api.AmzTaggingCount, strconv.Itoa(tagSetLength))

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

func (h *handler) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		info   *data.ObjectInfo
		params *layer.RangeParams

		reqInfo = api.GetReqInfo(r.Context())
	)

	args, err := parseGetObjectArgs(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse request params", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}

	if info, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	if err = checkPreconditions(info, args.Conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, err)
		return
	}

	if params, err = fetchRangeHeader(r.Header, uint64(info.Size)); err != nil {
		h.logAndSendError(w, "could not parse range header", reqInfo, err)
		return
	}

	tagSet, err := h.obj.GetObjectTagging(r.Context(), info)
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		h.logAndSendError(w, "could not get object tag set", reqInfo, err)
		return
	}

	if layer.IsAuthenticatedRequest(r.Context()) {
		overrideResponseHeaders(w.Header(), reqInfo.URL.Query())
	}

	if err = h.setLockingHeaders(r.Context(), bktInfo, info, w.Header()); err != nil {
		h.logAndSendError(w, "could not get locking info", reqInfo, err)
		return
	}

	writeHeaders(w.Header(), info, len(tagSet))
	if params != nil {
		writeRangeHeaders(w, params, info.Size)
	} else {
		w.WriteHeader(http.StatusOK)
	}

	getParams := &layer.GetObjectParams{
		ObjectInfo: info,
		Writer:     w,
		Range:      params,
		VersionID:  p.VersionID,
	}
	if err = h.obj.GetObject(r.Context(), getParams); err != nil {
		h.logAndSendError(w, "could not get object", reqInfo, err)
	}
}

func checkPreconditions(info *data.ObjectInfo, args *conditionalArgs) error {
	if len(args.IfMatch) > 0 && args.IfMatch != info.HashSum {
		return errors.GetAPIError(errors.ErrPreconditionFailed)
	}
	if len(args.IfNoneMatch) > 0 && args.IfNoneMatch == info.HashSum {
		return errors.GetAPIError(errors.ErrNotModified)
	}
	if args.IfModifiedSince != nil && info.Created.Before(*args.IfModifiedSince) {
		return errors.GetAPIError(errors.ErrNotModified)
	}
	if args.IfUnmodifiedSince != nil && info.Created.After(*args.IfUnmodifiedSince) {
		if len(args.IfMatch) == 0 {
			return errors.GetAPIError(errors.ErrPreconditionFailed)
		}
	}

	return nil
}

func parseGetObjectArgs(headers http.Header) (*getObjectArgs, error) {
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

	return &getObjectArgs{Conditional: args}, nil
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
