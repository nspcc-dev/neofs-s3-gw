package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"go.uber.org/zap"
)

type listObjectsArgs struct {
	Bucket    string
	Delimeter string
	Encode    string
	Marker    string
	MaxKeys   int
	Prefix    string
	Version   string
}

var maxObjectList = 10000 // Limit number of objects in a listObjectsResponse/listObjectsVersionsResponse.

func (h *handler) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		arg *listObjectsArgs
		res *ListObjectsResponse
		rid = api.GetRequestID(r.Context())
	)

	if arg, err = parseListObjectArgs(r); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrBadRequest).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusBadRequest,
		}, r.URL)

		return
	}

	list, err := h.obj.ListObjects(r.Context(), &layer.ListObjectsParams{
		Bucket:    arg.Bucket,
		Prefix:    arg.Prefix,
		MaxKeys:   arg.MaxKeys,
		Delimiter: arg.Delimeter,
	})
	if err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	}

	res = &ListObjectsResponse{
		Name:         arg.Bucket,
		EncodingType: arg.Encode,
		Marker:       arg.Marker,
		Prefix:       arg.Prefix,
		MaxKeys:      arg.MaxKeys,
		Delimiter:    arg.Delimeter,

		IsTruncated: list.IsTruncated,
		NextMarker:  list.NextContinuationToken,
	}

	// fill common prefixes
	for i := range list.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, CommonPrefix{
			Prefix: list.Prefixes[i],
		})
	}

	// fill contents
	for _, obj := range list.Objects {
		res.Contents = append(res.Contents, Object{
			Key:          obj.Name,
			Size:         obj.Size,
			UserMetadata: obj.Headers,
			LastModified: obj.Created.Format(time.RFC3339),

			// ETag:         "",
			// Owner:        Owner{},
			// StorageClass: "",
		})
	}

	if err := api.EncodeToResponse(w, res); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           "XNeoFSUnimplemented",
			Description:    "implement me " + mux.CurrentRoute(r).GetName(),
			HTTPStatusCode: http.StatusNotImplemented,
		}, r.URL)
	}
}

func parseListObjectArgs(r *http.Request) (*listObjectsArgs, error) {
	var (
		err error
		res listObjectsArgs
	)

	if r.URL.Query().Get("max-keys") == "" {
		res.MaxKeys = maxObjectList
	} else if res.MaxKeys, err = strconv.Atoi(r.URL.Query().Get("max-keys")); err != nil {
		return nil, api.GetAPIError(api.ErrInvalidMaxKeys)
	}

	res.Prefix = r.URL.Query().Get("prefix")
	res.Marker = r.URL.Query().Get("key-marker")
	res.Delimeter = r.URL.Query().Get("delimiter")
	res.Encode = r.URL.Query().Get("encoding-type")
	res.Version = r.URL.Query().Get("version-id-marker")

	if info := api.GetReqInfo(r.Context()); info != nil {
		res.Bucket = info.BucketName
	}

	return &res, nil
}
