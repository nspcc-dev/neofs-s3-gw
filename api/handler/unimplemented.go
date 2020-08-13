package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
)

func (h *handler) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) CopyObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutObjectPartHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) ListObjectPartsHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) NewMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutObjectACLHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutObjectRetentionHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutObjectLegalHoldHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutObjectHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketACLHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketAccelerateHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketLoggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketReplicationHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketWebsiteHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) GetBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) ListenBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) ListBucketObjectVersionsHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketObjectLockConfigHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketNotificationHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PutBucketHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) PostPolicyBucketHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketPolicyHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketEncryptionHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}

func (h *handler) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	api.WriteErrorResponse(r.Context(), w, api.Error{
		Code:           "XNeoFSUnimplemented",
		Description:    "implement me " + mux.CurrentRoute(r).GetName(),
		HTTPStatusCode: http.StatusNotImplemented,
	}, r.URL)
}
