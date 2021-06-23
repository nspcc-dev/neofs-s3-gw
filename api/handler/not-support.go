package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api"
)

func (h *handler) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           api.GetAPIError(api.ErrBadRequest).Code,
		Description:    notSupported + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}
