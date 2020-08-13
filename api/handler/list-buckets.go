package handler

import (
	"net/http"
	"time"

	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
	"go.uber.org/zap"
)

func (h *handler) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		res *ListBucketsResponse
		rid = api.GetRequestID(r.Context())
	)

	tkn, err := auth.GetBearerToken(r.Context())
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
			ID:          tkn.OwnerID.String(),
			DisplayName: tkn.OwnerID.String(),
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
