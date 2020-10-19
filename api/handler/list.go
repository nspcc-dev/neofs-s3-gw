package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
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

func (h *handler) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		own = owner.NewID()
		tkn *token.BearerToken
		res *ListBucketsResponse
		rid = api.GetRequestID(r.Context())
	)

	if tkn, err = auth.GetBearerToken(r.Context()); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)

		return
	} else if own, err = layer.GetOwnerID(tkn); err != nil {
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

	list, err := h.obj.ListBuckets(r.Context())
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

	res = &ListBucketsResponse{
		Owner: Owner{
			ID:          own.String(),
			DisplayName: own.String(),
		},
	}

	for _, item := range list {
		res.Buckets.Buckets = append(res.Buckets.Buckets, Bucket{
			Name:         item.Name,
			CreationDate: item.Created.Format(time.RFC3339),
		})
	}

	if err = api.EncodeToResponse(w, res); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

func (h *handler) listObjects(w http.ResponseWriter, r *http.Request) (*listObjectsArgs, *layer.ListObjectsInfo, error) {
	var (
		err error
		arg *listObjectsArgs
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

		return nil, nil, err
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

		return nil, nil, err
	}

	return arg, list, nil
}

func (h *handler) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	var rid = api.GetRequestID(r.Context())
	if arg, list, err := h.listObjects(w, r); err != nil {
		// error already sent to client
		return
	} else if err := api.EncodeToResponse(w, encodeV1(arg, list)); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

func encodeV1(arg *listObjectsArgs, list *layer.ListObjectsInfo) *ListObjectsResponse {
	res := &ListObjectsResponse{
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

			Owner: Owner{
				ID:          obj.Owner.String(),
				DisplayName: obj.Owner.String(),
			},

			// ETag:         "",
			// StorageClass: "",
		})
	}

	return res
}

func (h *handler) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	var rid = api.GetRequestID(r.Context())
	if arg, list, err := h.listObjects(w, r); err != nil {
		// error already sent to client
		return
	} else if err := api.EncodeToResponse(w, encodeV2(arg, list)); err != nil {
		h.log.Error("something went wrong",
			zap.String("request_id", rid),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}

func encodeV2(arg *listObjectsArgs, list *layer.ListObjectsInfo) *ListObjectsV2Response {
	res := &ListObjectsV2Response{
		Name:         arg.Bucket,
		EncodingType: arg.Encode,
		Prefix:       arg.Prefix,
		MaxKeys:      arg.MaxKeys,
		Delimiter:    arg.Delimeter,

		IsTruncated: list.IsTruncated,

		ContinuationToken:     arg.Marker,
		NextContinuationToken: list.NextContinuationToken,
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

			Owner: Owner{
				ID:          obj.Owner.String(),
				DisplayName: obj.Owner.String(),
			},

			// ETag:         "",
			// StorageClass: "",
		})
	}

	return res
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
