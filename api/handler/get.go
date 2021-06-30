package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

type (
	detector struct {
		io.Writer
		sync.Once

		contentType string
	}
)

func newDetector(w io.Writer) *detector {
	return &detector{Writer: w}
}

func (d *detector) Write(data []byte) (int, error) {
	d.Once.Do(func() {
		d.contentType = http.DetectContentType(data)
		if rw, ok := d.Writer.(http.ResponseWriter); ok {
			rw.WriteHeader(http.StatusOK)
			if len(rw.Header().Get(api.ContentType)) == 0 {
				rw.Header().Set(api.ContentType, d.contentType)
			}
		}
	})

	return d.Writer.Write(data)
}

func (h *handler) contentTypeFetcher(ctx context.Context, w io.Writer, info *layer.ObjectInfo) (string, error) {
	return h.contentTypeFetcherWithRange(ctx, w, info, nil)
}

func (h *handler) contentTypeFetcherWithRange(ctx context.Context, w io.Writer, info *layer.ObjectInfo, rangeParams *layer.RangeParams) (string, error) {
	if info.IsDir() {
		if rangeParams != nil {
			return "", fmt.Errorf("it is forbidden to request for a range in the directory")
		}
		return info.ContentType, nil
	}

	writer := newDetector(w)

	params := &layer.GetObjectParams{
		Bucket: info.Bucket,
		Object: info.Name,
		Writer: writer,
		Range:  rangeParams,
	}

	// params.Length = inf.Size

	if err := h.obj.GetObject(ctx, params); err != nil {
		return "", err
	}

	return writer.contentType, nil
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
	h.Set("Content-Type", info.ContentType)
	h.Set("Last-Modified", info.Created.Format(http.TimeFormat))
	h.Set("Content-Length", strconv.FormatInt(info.Size, 10))

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

	if inf, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err != nil {
		writeError(w, r, h.log, "could not find object", rid, bkt, obj, err)
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
	if inf.ContentType, err = h.contentTypeFetcherWithRange(r.Context(), w, inf, params); err != nil {
		writeError(w, r, h.log, "could not get object", rid, bkt, obj, err)
		return
	}
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
