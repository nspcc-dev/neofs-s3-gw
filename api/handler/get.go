package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
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

func writeHeaders(h http.Header, info *layer.ObjectInfo) {
	if len(info.ContentType) > 0 {
		h.Set(api.ContentType, info.ContentType)
	}
	h.Set(api.LastModified, info.Created.UTC().Format(http.TimeFormat))
	h.Set(api.ContentLength, strconv.FormatInt(info.Size, 10))
	h.Set(api.ETag, info.HashSum)
	h.Set(api.AmzVersionId, info.ID().String())

	for key, val := range info.Headers {
		h[api.MetadataPrefix+key] = []string{val}
	}
}

func (h *handler) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		inf    *layer.ObjectInfo
		params *layer.RangeParams

		reqInfo = api.GetReqInfo(r.Context())
	)

	args, err := parseGetObjectArgs(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse request params", reqInfo, err)
		return
	}

	if err = h.checkBucketOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		Bucket:    reqInfo.BucketName,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	if inf, err = h.obj.GetObjectInfo(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not find object", reqInfo, err)
		return
	}

	if err = checkPreconditions(inf, args.Conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, err)
		return
	}

	if params, err = fetchRangeHeader(r.Header, uint64(inf.Size)); err != nil {
		h.logAndSendError(w, "could not parse range header", reqInfo, err)
		return
	}
	writeHeaders(w.Header(), inf)
	if params != nil {
		writeRangeHeaders(w, params, inf.Size)
	}

	getParams := &layer.GetObjectParams{
		ObjectInfo: inf,
		Writer:     w,
		Range:      params,
		VersionID:  p.VersionID,
	}
	if err = h.obj.GetObject(r.Context(), getParams); err != nil {
		h.logAndSendError(w, "could not get object", reqInfo, err)
	}
}

func checkPreconditions(inf *layer.ObjectInfo, args *conditionalArgs) error {
	if len(args.IfMatch) > 0 && args.IfMatch != inf.HashSum {
		return errors.GetAPIError(errors.ErrPreconditionFailed)
	}
	if len(args.IfNoneMatch) > 0 && args.IfNoneMatch == inf.HashSum {
		return errors.GetAPIError(errors.ErrNotModified)
	}
	if args.IfModifiedSince != nil && inf.Created.Before(*args.IfModifiedSince) {
		return errors.GetAPIError(errors.ErrNotModified)
	}
	if args.IfUnmodifiedSince != nil && inf.Created.After(*args.IfUnmodifiedSince) {
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
