package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/minio/minio/auth"
	"github.com/minio/minio/neofs/metrics"
	"go.uber.org/zap"
)

type (
	Handler interface {
		HeadObjectHandler(http.ResponseWriter, *http.Request)
		CopyObjectPartHandler(http.ResponseWriter, *http.Request)
		PutObjectPartHandler(http.ResponseWriter, *http.Request)
		ListObjectPartsHandler(http.ResponseWriter, *http.Request)
		CompleteMultipartUploadHandler(http.ResponseWriter, *http.Request)
		NewMultipartUploadHandler(http.ResponseWriter, *http.Request)
		AbortMultipartUploadHandler(http.ResponseWriter, *http.Request)
		GetObjectACLHandler(http.ResponseWriter, *http.Request)
		PutObjectACLHandler(http.ResponseWriter, *http.Request)
		GetObjectTaggingHandler(http.ResponseWriter, *http.Request)
		PutObjectTaggingHandler(http.ResponseWriter, *http.Request)
		DeleteObjectTaggingHandler(http.ResponseWriter, *http.Request)
		SelectObjectContentHandler(http.ResponseWriter, *http.Request)
		GetObjectRetentionHandler(http.ResponseWriter, *http.Request)
		GetObjectLegalHoldHandler(http.ResponseWriter, *http.Request)
		GetObjectHandler(http.ResponseWriter, *http.Request)
		CopyObjectHandler(http.ResponseWriter, *http.Request)
		PutObjectRetentionHandler(http.ResponseWriter, *http.Request)
		PutObjectLegalHoldHandler(http.ResponseWriter, *http.Request)
		PutObjectHandler(http.ResponseWriter, *http.Request)
		DeleteObjectHandler(http.ResponseWriter, *http.Request)
		GetBucketLocationHandler(http.ResponseWriter, *http.Request)
		GetBucketPolicyHandler(http.ResponseWriter, *http.Request)
		GetBucketLifecycleHandler(http.ResponseWriter, *http.Request)
		GetBucketEncryptionHandler(http.ResponseWriter, *http.Request)
		GetBucketACLHandler(http.ResponseWriter, *http.Request)
		PutBucketACLHandler(http.ResponseWriter, *http.Request)
		GetBucketCorsHandler(http.ResponseWriter, *http.Request)
		GetBucketWebsiteHandler(http.ResponseWriter, *http.Request)
		GetBucketAccelerateHandler(http.ResponseWriter, *http.Request)
		GetBucketRequestPaymentHandler(http.ResponseWriter, *http.Request)
		GetBucketLoggingHandler(http.ResponseWriter, *http.Request)
		GetBucketReplicationHandler(http.ResponseWriter, *http.Request)
		GetBucketTaggingHandler(http.ResponseWriter, *http.Request)
		DeleteBucketWebsiteHandler(http.ResponseWriter, *http.Request)
		DeleteBucketTaggingHandler(http.ResponseWriter, *http.Request)
		GetBucketObjectLockConfigHandler(http.ResponseWriter, *http.Request)
		GetBucketVersioningHandler(http.ResponseWriter, *http.Request)
		GetBucketNotificationHandler(http.ResponseWriter, *http.Request)
		ListenBucketNotificationHandler(http.ResponseWriter, *http.Request)
		ListMultipartUploadsHandler(http.ResponseWriter, *http.Request)
		ListObjectsV2MHandler(http.ResponseWriter, *http.Request)
		ListObjectsV2Handler(http.ResponseWriter, *http.Request)
		ListBucketObjectVersionsHandler(http.ResponseWriter, *http.Request)
		ListObjectsV1Handler(http.ResponseWriter, *http.Request)
		PutBucketLifecycleHandler(http.ResponseWriter, *http.Request)
		PutBucketEncryptionHandler(http.ResponseWriter, *http.Request)
		PutBucketPolicyHandler(http.ResponseWriter, *http.Request)
		PutBucketObjectLockConfigHandler(http.ResponseWriter, *http.Request)
		PutBucketTaggingHandler(http.ResponseWriter, *http.Request)
		PutBucketVersioningHandler(http.ResponseWriter, *http.Request)
		PutBucketNotificationHandler(http.ResponseWriter, *http.Request)
		PutBucketHandler(http.ResponseWriter, *http.Request)
		HeadBucketHandler(http.ResponseWriter, *http.Request)
		PostPolicyBucketHandler(http.ResponseWriter, *http.Request)
		DeleteMultipleObjectsHandler(http.ResponseWriter, *http.Request)
		DeleteBucketPolicyHandler(http.ResponseWriter, *http.Request)
		DeleteBucketLifecycleHandler(http.ResponseWriter, *http.Request)
		DeleteBucketEncryptionHandler(http.ResponseWriter, *http.Request)
		DeleteBucketHandler(http.ResponseWriter, *http.Request)
		ListBucketsHandler(http.ResponseWriter, *http.Request)
	}

	// mimeType represents various MIME type used API responses.
	mimeType string
)

const (

	// SlashSeparator - slash separator.
	SlashSeparator = "/"

	// Means no response type.
	mimeNone mimeType = ""
	// Means response type is JSON.
	// mimeJSON mimeType = "application/json"
	// Means response type is XML.
	mimeXML mimeType = "application/xml"
)

func Attach(r *mux.Router, m MaxClients, h Handler, center *auth.Center, log *zap.Logger) {
	api := r.PathPrefix(SlashSeparator).Subrouter()
	// Attach user authentication for all S3 routes.
	AttachUserAuth(api, center, log)

	bucket := api.PathPrefix("/{bucket}").Subrouter()

	// Object operations
	// HeadObject
	bucket.Methods(http.MethodHead).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("headobject", h.HeadObjectHandler)))
	// CopyObjectPart
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(hdrAmzCopySource, ".*?(\\/|%2F).*?").HandlerFunc(m.Handle(metrics.APIStats("copyobjectpart", h.CopyObjectPartHandler))).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
	// PutObjectPart
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("putobjectpart", h.PutObjectPartHandler))).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
	// ListObjectParts
	bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("listobjectparts", h.ListObjectPartsHandler))).Queries("uploadId", "{uploadId:.*}")
	// CompleteMultipartUpload
	bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("completemutipartupload", h.CompleteMultipartUploadHandler))).Queries("uploadId", "{uploadId:.*}")
	// NewMultipartUpload
	bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("newmultipartupload", h.NewMultipartUploadHandler))).Queries("uploads", "")
	// AbortMultipartUpload
	bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("abortmultipartupload", h.AbortMultipartUploadHandler))).Queries("uploadId", "{uploadId:.*}")
	// GetObjectACL - this is a dummy call.
	bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("getobjectacl", h.GetObjectACLHandler))).Queries("acl", "")
	// PutObjectACL - this is a dummy call.
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("putobjectacl", h.PutObjectACLHandler))).Queries("acl", "")
	// GetObjectTagging
	bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("getobjecttagging", h.GetObjectTaggingHandler))).Queries("tagging", "")
	// PutObjectTagging
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("putobjecttagging", h.PutObjectTaggingHandler))).Queries("tagging", "")
	// DeleteObjectTagging
	bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("deleteobjecttagging", h.DeleteObjectTaggingHandler))).Queries("tagging", "")
	// SelectObjectContent
	bucket.Methods(http.MethodPost).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("selectobjectcontent", h.SelectObjectContentHandler))).Queries("select", "").Queries("select-type", "2")
	// GetObjectRetention
	bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("getobjectretention", h.GetObjectRetentionHandler))).Queries("retention", "")
	// GetObjectLegalHold
	bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("getobjectlegalhold", h.GetObjectLegalHoldHandler))).Queries("legal-hold", "")
	// GetObject
	bucket.Methods(http.MethodGet).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("getobject", h.GetObjectHandler)))
	// CopyObject
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HeadersRegexp(hdrAmzCopySource, ".*?(\\/|%2F).*?").HandlerFunc(m.Handle(metrics.APIStats("copyobject", h.CopyObjectHandler)))
	// PutObjectRetention
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("putobjectretention", h.PutObjectRetentionHandler))).Queries("retention", "")
	// PutObjectLegalHold
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("putobjectlegalhold", h.PutObjectLegalHoldHandler))).Queries("legal-hold", "")

	// PutObject
	bucket.Methods(http.MethodPut).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("putobject", h.PutObjectHandler)))
	// DeleteObject
	bucket.Methods(http.MethodDelete).Path("/{object:.+}").HandlerFunc(
		m.Handle(metrics.APIStats("deleteobject", h.DeleteObjectHandler)))

	// Bucket operations
	// GetBucketLocation
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketlocation", h.GetBucketLocationHandler))).Queries("location", "")
	// GetBucketPolicy
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketpolicy", h.GetBucketPolicyHandler))).Queries("policy", "")
	// GetBucketLifecycle
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketlifecycle", h.GetBucketLifecycleHandler))).Queries("lifecycle", "")
	// GetBucketEncryption
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketencryption", h.GetBucketEncryptionHandler))).Queries("encryption", "")

	// Dummy Bucket Calls
	// GetBucketACL -- this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketacl", h.GetBucketACLHandler))).Queries("acl", "")
	// PutBucketACL -- this is a dummy call.
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketacl", h.PutBucketACLHandler))).Queries("acl", "")
	// GetBucketCors - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketcors", h.GetBucketCorsHandler))).Queries("cors", "")
	// GetBucketWebsiteHandler - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketwebsite", h.GetBucketWebsiteHandler))).Queries("website", "")
	// GetBucketAccelerateHandler - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketaccelerate", h.GetBucketAccelerateHandler))).Queries("accelerate", "")
	// GetBucketRequestPaymentHandler - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketrequestpayment", h.GetBucketRequestPaymentHandler))).Queries("requestPayment", "")
	// GetBucketLoggingHandler - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketlogging", h.GetBucketLoggingHandler))).Queries("logging", "")
	// GetBucketLifecycleHandler - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketlifecycle", h.GetBucketLifecycleHandler))).Queries("lifecycle", "")
	// GetBucketReplicationHandler - this is a dummy call.
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketreplication", h.GetBucketReplicationHandler))).Queries("replication", "")
	// GetBucketTaggingHandler
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbuckettagging", h.GetBucketTaggingHandler))).Queries("tagging", "")
	// DeleteBucketWebsiteHandler
	bucket.Methods(http.MethodDelete).HandlerFunc(
		m.Handle(metrics.APIStats("deletebucketwebsite", h.DeleteBucketWebsiteHandler))).Queries("website", "")
	// DeleteBucketTaggingHandler
	bucket.Methods(http.MethodDelete).HandlerFunc(
		m.Handle(metrics.APIStats("deletebuckettagging", h.DeleteBucketTaggingHandler))).Queries("tagging", "")

	// GetBucketObjectLockConfig
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketobjectlockconfiguration", h.GetBucketObjectLockConfigHandler))).Queries("object-lock", "")
	// GetBucketVersioning
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketversioning", h.GetBucketVersioningHandler))).Queries("versioning", "")
	// GetBucketNotification
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("getbucketnotification", h.GetBucketNotificationHandler))).Queries("notification", "")
	// ListenBucketNotification
	bucket.Methods(http.MethodGet).HandlerFunc(metrics.APIStats("listenbucketnotification", h.ListenBucketNotificationHandler)).Queries("events", "{events:.*}")
	// ListMultipartUploads
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("listmultipartuploads", h.ListMultipartUploadsHandler))).Queries("uploads", "")
	// ListObjectsV2M
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("listobjectsv2M", h.ListObjectsV2MHandler))).Queries("list-type", "2", "metadata", "true")
	// ListObjectsV2
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("listobjectsv2", h.ListObjectsV2Handler))).Queries("list-type", "2")
	// ListBucketVersions
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("listbucketversions", h.ListBucketObjectVersionsHandler))).Queries("versions", "")
	// ListObjectsV1 (Legacy)
	bucket.Methods(http.MethodGet).HandlerFunc(
		m.Handle(metrics.APIStats("listobjectsv1", h.ListObjectsV1Handler)))
	// PutBucketLifecycle
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketlifecycle", h.PutBucketLifecycleHandler))).Queries("lifecycle", "")
	// PutBucketEncryption
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketencryption", h.PutBucketEncryptionHandler))).Queries("encryption", "")

	// PutBucketPolicy
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketpolicy", h.PutBucketPolicyHandler))).Queries("policy", "")

	// PutBucketObjectLockConfig
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketobjectlockconfig", h.PutBucketObjectLockConfigHandler))).Queries("object-lock", "")
	// PutBucketTaggingHandler
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbuckettagging", h.PutBucketTaggingHandler))).Queries("tagging", "")
	// PutBucketVersioning
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketversioning", h.PutBucketVersioningHandler))).Queries("versioning", "")
	// PutBucketNotification
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucketnotification", h.PutBucketNotificationHandler))).Queries("notification", "")
	// PutBucket
	bucket.Methods(http.MethodPut).HandlerFunc(
		m.Handle(metrics.APIStats("putbucket", h.PutBucketHandler)))
	// HeadBucket
	bucket.Methods(http.MethodHead).HandlerFunc(
		m.Handle(metrics.APIStats("headbucket", h.HeadBucketHandler)))
	// PostPolicy
	bucket.Methods(http.MethodPost).HeadersRegexp(hdrContentType, "multipart/form-data*").HandlerFunc(
		m.Handle(metrics.APIStats("postpolicybucket", h.PostPolicyBucketHandler)))
	// DeleteMultipleObjects
	bucket.Methods(http.MethodPost).HandlerFunc(
		m.Handle(metrics.APIStats("deletemultipleobjects", h.DeleteMultipleObjectsHandler))).Queries("delete", "")
	// DeleteBucketPolicy
	bucket.Methods(http.MethodDelete).HandlerFunc(
		m.Handle(metrics.APIStats("deletebucketpolicy", h.DeleteBucketPolicyHandler))).Queries("policy", "")
	// DeleteBucketLifecycle
	bucket.Methods(http.MethodDelete).HandlerFunc(
		m.Handle(metrics.APIStats("deletebucketlifecycle", h.DeleteBucketLifecycleHandler))).Queries("lifecycle", "")
	// DeleteBucketEncryption
	bucket.Methods(http.MethodDelete).HandlerFunc(
		m.Handle(metrics.APIStats("deletebucketencryption", h.DeleteBucketEncryptionHandler))).Queries("encryption", "")
	// DeleteBucket
	bucket.Methods(http.MethodDelete).HandlerFunc(
		m.Handle(metrics.APIStats("deletebucket", h.DeleteBucketHandler)))

	// Root operation

	// ListBuckets
	api.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
		m.Handle(metrics.APIStats("listbuckets", h.ListBucketsHandler)))

	// S3 browser with signature v4 adds '//' for ListBuckets request, so rather
	// than failing with UnknownAPIRequest we simply handle it for now.
	api.Methods(http.MethodGet).Path(SlashSeparator + SlashSeparator).HandlerFunc(
		m.Handle(metrics.APIStats("listbuckets", h.ListBucketsHandler)))

	// If none of the routes match add default error handler routes
	api.NotFoundHandler = metrics.APIStats("notfound", errorResponseHandler)
	api.MethodNotAllowedHandler = metrics.APIStats("methodnotallowed", errorResponseHandler)
}
