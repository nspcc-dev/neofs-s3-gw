package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
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
	}

	if err0 != nil || err1 != nil || start > end {
		return nil, fmt.Errorf("invalid Range header")
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

	for key, val := range info.Headers {
		h.Set("X-"+key, val)
	}
}

func (h *handler) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		inf    *layer.ObjectInfo
		params *layer.RangeParams

		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	args, err := parseGetObjectArgs(r.Header)
	if err != nil {
		writeError(w, r, h.log, "could not parse request params", rid, bkt, obj, err)
		return
	}

	if inf, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err != nil {
		writeError(w, r, h.log, "could not find object", rid, bkt, obj, err)
		return
	}

	status := checkPreconditions(inf, args.Conditional)
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	if params, err = fetchRangeHeader(r.Header, uint64(inf.Size)); err != nil {
		writeError(w, r, h.log, "could not parse range header", rid, bkt, obj, err)
		return
	}
	writeHeaders(w.Header(), inf)
	if params != nil {
		writeRangeHeaders(w, params, inf.Size)
	}

	getParams := &layer.GetObjectParams{
		Bucket: inf.Bucket,
		Object: inf.Name,
		Writer: w,
		Range:  params,
	}
	if err = h.obj.GetObject(r.Context(), getParams); err != nil {
		writeError(w, r, h.log, "could not get object", rid, bkt, obj, err)
	}
}

func checkPreconditions(inf *layer.ObjectInfo, args *conditionalArgs) int {
	if len(args.IfMatch) > 0 && args.IfMatch != inf.HashSum {
		return http.StatusPreconditionFailed
	}
	if len(args.IfNoneMatch) > 0 && args.IfNoneMatch == inf.HashSum {
		return http.StatusNotModified
	}
	if args.IfModifiedSince != nil && inf.Created.Before(*args.IfModifiedSince) {
		return http.StatusNotModified
	}
	if args.IfUnmodifiedSince != nil && inf.Created.After(*args.IfUnmodifiedSince) {
		if len(args.IfMatch) == 0 {
			return http.StatusPreconditionFailed
		}
	}

	return http.StatusOK
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
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", params.Start, params.End, size))
	w.WriteHeader(http.StatusPartialContent)
}

func writeError(w http.ResponseWriter, r *http.Request, log *zap.Logger, msg, rid, bkt, obj string, err error) {
	log.Error(msg,
		zap.String("request_id", rid),
		zap.String("bucket_name", bkt),
		zap.String("object_name", obj),
		zap.Error(err))

	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrInternalError).Code,
		Description:    err.Error(),
		HTTPStatusCode: http.StatusInternalServerError,
	}, r.URL)
}
