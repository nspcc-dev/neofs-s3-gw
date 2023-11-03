package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
)

func (h *handler) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}

func (h *handler) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}

func (h *handler) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}

func (h *handler) GetObjectTorrentHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}

func (h *handler) GetBucketPolicyStatusHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}

func (h *handler) PutPublicAccessBlockHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}

func (h *handler) GetPublicAccessBlockHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not supported", api.GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrNotSupported))
}
