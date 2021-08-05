package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
)

func (h *handler) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), api.GetAPIError(api.ErrNotSupported))
}

func (h *handler) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), api.GetAPIError(api.ErrNotSupported))
}

func (h *handler) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), api.GetAPIError(api.ErrNotSupported))
}

func (h *handler) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), api.GetAPIError(api.ErrNotSupported))
}

func (h *handler) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), api.GetAPIError(api.ErrNotSupported))
}

func (h *handler) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), api.GetAPIError(api.ErrNotSupported))
}
