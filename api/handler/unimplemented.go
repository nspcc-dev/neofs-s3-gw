package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
)

func (h *handler) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketReplicationHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) ListenBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}

func (h *handler) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	h.logAndSendError(w, "not implemented", api.GetReqInfo(r.Context()), errors.GetAPIError(errors.ErrNotImplemented))
}
