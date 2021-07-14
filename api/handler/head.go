package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

const sizeToDetectType = 512

func getRangeToDetectContentType(maxSize int64) *layer.RangeParams {
	end := uint64(maxSize)
	if sizeToDetectType < end {
		end = sizeToDetectType
	}

	return &layer.RangeParams{
		Start: 0,
		End:   end - 1,
	}
}

func (h *handler) checkIsFolder(ctx context.Context, bucket, object string) *layer.ObjectInfo {
	if ln := len(object); ln > 0 && object[ln-1:] != layer.PathSeparator {
		return nil
	}

	_, dirname := layer.NameFromString(object)
	params := &layer.ListObjectsParamsV1{
		ListObjectsParamsCommon: layer.ListObjectsParamsCommon{
			Bucket:    bucket,
			Prefix:    dirname,
			Delimiter: layer.PathSeparator,
		}}
	if list, err := h.obj.ListObjectsV1(ctx, params); err == nil && len(list.Objects) > 0 {
		return &layer.ObjectInfo{
			Bucket: bucket,
			Name:   object,

			ContentType: "text/directory",

			Owner:   list.Objects[0].Owner,
			Created: list.Objects[0].Created,
		}
	}

	return nil
}

func (h *handler) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		inf *layer.ObjectInfo

		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	if inf = h.checkIsFolder(r.Context(), bkt, obj); inf != nil {
		// do nothing for folders

		// h.log.Debug("found folder",
		// 	zap.String("request_id", rid),
		// 	zap.String("bucket_name", bkt),
		// 	zap.String("object_name", obj))
	} else if inf, err = h.obj.GetObjectInfo(r.Context(), bkt, obj); err != nil {
		h.log.Error("could not fetch object info",
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
	buffer := bytes.NewBuffer(make([]byte, 0, sizeToDetectType))
	getParams := &layer.GetObjectParams{
		Bucket: inf.Bucket,
		Object: inf.Name,
		Writer: buffer,
		Range:  getRangeToDetectContentType(inf.Size),
	}
	if err = h.obj.GetObject(r.Context(), getParams); err != nil {
		h.log.Error("could not get object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Stringer("oid", inf.ID()),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}
	inf.ContentType = http.DetectContentType(buffer.Bytes())
	writeHeaders(w.Header(), inf)
	w.WriteHeader(http.StatusOK)
}

func (h *handler) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	var (
		req = mux.Vars(r)
		bkt = req["bucket"]
		rid = api.GetRequestID(r.Context())
	)

	if _, err := h.obj.GetBucketInfo(r.Context(), bkt); err != nil {
		h.log.Error("could not fetch object info",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.Error(err))

		code := http.StatusBadRequest
		if errors.Is(err, layer.ErrBucketNotFound) {
			code = http.StatusNotFound
		}

		api.WriteResponse(w, code, nil, api.MimeNone)

		return
	}

	api.WriteResponse(w, http.StatusOK, nil, api.MimeNone)
}
