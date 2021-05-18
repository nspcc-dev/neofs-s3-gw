package handler

import (
	"context"
	"io"
	"net/http"
	"strconv"
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
		if rw, ok := d.Writer.(http.ResponseWriter); ok {
			rw.WriteHeader(http.StatusOK)
		}

		d.contentType = http.DetectContentType(data)
	})

	return d.Writer.Write(data)
}

func (h *handler) contentTypeFetcher(ctx context.Context, w io.Writer, info *layer.ObjectInfo) (string, error) {
	if info.IsDir() {
		return info.ContentType, nil
	}

	writer := newDetector(w)

	params := &layer.GetObjectParams{
		Bucket: info.Bucket,
		Object: info.Name,
		Writer: writer,
	}

	// params.Length = inf.Size

	if err := h.obj.GetObject(ctx, params); err != nil {
		return "", err
	}

	return writer.contentType, nil
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
		err error
		inf *layer.ObjectInfo

		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	if inf, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err != nil {
		h.log.Error("could not find object",
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
	} else if inf.ContentType, err = h.contentTypeFetcher(r.Context(), w, inf); err != nil {
		h.log.Error("could not get object",
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
	}

	writeHeaders(w.Header(), inf)
}
