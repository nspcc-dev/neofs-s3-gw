package api

import (
	"context"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/nspcc-dev/neofs-s3-gw/api/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

type (
	// Handler is an S3 API handler interface.
	Handler interface {
		HeadObjectHandler(http.ResponseWriter, *http.Request)
		GetObjectACLHandler(http.ResponseWriter, *http.Request)
		PutObjectACLHandler(http.ResponseWriter, *http.Request)
		GetObjectTaggingHandler(http.ResponseWriter, *http.Request)
		PutObjectTaggingHandler(http.ResponseWriter, *http.Request)
		DeleteObjectTaggingHandler(http.ResponseWriter, *http.Request)
		SelectObjectContentHandler(http.ResponseWriter, *http.Request)
		GetObjectRetentionHandler(http.ResponseWriter, *http.Request)
		GetObjectLegalHoldHandler(http.ResponseWriter, *http.Request)
		GetObjectHandler(http.ResponseWriter, *http.Request)
		GetObjectAttributesHandler(http.ResponseWriter, *http.Request)
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
		PutBucketCorsHandler(http.ResponseWriter, *http.Request)
		DeleteBucketCorsHandler(http.ResponseWriter, *http.Request)
		GetBucketWebsiteHandler(http.ResponseWriter, *http.Request)
		GetBucketAccelerateHandler(http.ResponseWriter, *http.Request)
		GetBucketRequestPaymentHandler(http.ResponseWriter, *http.Request)
		GetBucketLoggingHandler(http.ResponseWriter, *http.Request)
		PutBucketLoggingHandler(http.ResponseWriter, *http.Request)
		GetBucketReplicationHandler(http.ResponseWriter, *http.Request)
		GetBucketTaggingHandler(http.ResponseWriter, *http.Request)
		DeleteBucketWebsiteHandler(http.ResponseWriter, *http.Request)
		DeleteBucketTaggingHandler(http.ResponseWriter, *http.Request)
		GetBucketObjectLockConfigHandler(http.ResponseWriter, *http.Request)
		GetBucketVersioningHandler(http.ResponseWriter, *http.Request)
		GetBucketNotificationHandler(http.ResponseWriter, *http.Request)
		ListenBucketNotificationHandler(http.ResponseWriter, *http.Request)
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
		CreateBucketHandler(http.ResponseWriter, *http.Request)
		HeadBucketHandler(http.ResponseWriter, *http.Request)
		PostObject(http.ResponseWriter, *http.Request)
		DeleteMultipleObjectsHandler(http.ResponseWriter, *http.Request)
		DeleteBucketPolicyHandler(http.ResponseWriter, *http.Request)
		GetBucketPolicyStatusHandler(http.ResponseWriter, *http.Request)
		DeleteBucketLifecycleHandler(http.ResponseWriter, *http.Request)
		DeleteBucketEncryptionHandler(http.ResponseWriter, *http.Request)
		DeleteBucketHandler(http.ResponseWriter, *http.Request)
		ListBucketsHandler(http.ResponseWriter, *http.Request)
		Preflight(w http.ResponseWriter, r *http.Request)
		AppendCORSHeaders(w http.ResponseWriter, r *http.Request)
		CreateMultipartUploadHandler(http.ResponseWriter, *http.Request)
		UploadPartHandler(http.ResponseWriter, *http.Request)
		UploadPartCopy(w http.ResponseWriter, r *http.Request)
		CompleteMultipartUploadHandler(http.ResponseWriter, *http.Request)
		AbortMultipartUploadHandler(http.ResponseWriter, *http.Request)
		ListPartsHandler(w http.ResponseWriter, r *http.Request)
		ListMultipartUploadsHandler(http.ResponseWriter, *http.Request)
		GetObjectTorrentHandler(http.ResponseWriter, *http.Request)
		PutPublicAccessBlockHandler(http.ResponseWriter, *http.Request)
		GetPublicAccessBlockHandler(http.ResponseWriter, *http.Request)
		PutBucketOwnershipControlsHandler(http.ResponseWriter, *http.Request)
		GetBucketOwnershipControlsHandler(http.ResponseWriter, *http.Request)
		DeleteBucketOwnershipControlsHandler(http.ResponseWriter, *http.Request)
	}

	// mimeType represents various MIME types used in API responses.
	mimeType string

	logResponseWriter struct {
		sync.Once
		http.ResponseWriter

		statusCode int
		sentCode   int
	}

	writerStatus interface{ Status() int }
)

const (
	// SlashSeparator -- slash separator.
	SlashSeparator = "/"

	// MimeNone means no response type.
	MimeNone mimeType = ""

	// MimeXML means response type is XML.
	MimeXML mimeType = "application/xml"
)

var _ = logErrorResponse

func (lrw *logResponseWriter) WriteHeader(code int) {
	// only the first code reaches the client, but the last one is what the
	// request has actually resulted in, so keep tracking it for the log.
	lrw.statusCode = code
	lrw.Do(func() {
		lrw.sentCode = code
		lrw.ResponseWriter.WriteHeader(code)
	})
}

// Status returns the status code sent to the client, zero if the response
// header is not written yet.
func (lrw *logResponseWriter) Status() int {
	return lrw.sentCode
}

func setRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// generate random UUIDv4
		id, _ := uuid.NewRandom()

		// set request id into response header
		w.Header().Set(hdrAmzRequestID, id.String())

		// set request id into gRPC meta header
		ctx := metadata.AppendToOutgoingContext(r.Context(), hdrAmzRequestID, id.String())

		// set request info into context
		ctx = prepareContext(ctx, w, r) //nolint:contextcheck // In fact, r.Context() is reused internally

		// continue execution
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func appendCORS(handler Handler) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.AppendCORSHeaders(w, r)
			h.ServeHTTP(w, r)
		})
	}
}

func appendPreflight(handler Handler) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.Preflight(w, r)
			if www, ok := w.(*logResponseWriter); ok {
				if www.statusCode != 0 {
					return
				}
			}

			h.ServeHTTP(w, r)
		})
	}
}

func logErrorResponse(l *zap.Logger) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lw := &logResponseWriter{ResponseWriter: w}
			reqInfo := GetReqInfo(r.Context())

			l.Info("call method",
				zap.String("host", r.Host),
				zap.String("request_id", reqInfo.RequestID),
				zap.String("method", mux.CurrentRoute(r).GetName()),
				zap.String("bucket", reqInfo.BucketName),
				zap.String("object", reqInfo.ObjectName),
			)

			// pass execution:
			h.ServeHTTP(lw, r)

			// Ignore >400 status codes
			if lw.statusCode >= http.StatusBadRequest {
				return
			}

			l.Info("call method result",
				zap.String("request_id", reqInfo.RequestID),
				zap.Int("status", lw.statusCode),
				zap.String("description", http.StatusText(lw.statusCode)))
		})
	}
}

// GetContextRequestID returns the request ID from the context.
func GetContextRequestID(ctx context.Context) string {
	return GetReqInfo(ctx).RequestID
}

// GetWriterRequestID extracts request ID from the response writer.
func GetWriterRequestID(w http.ResponseWriter) string {
	return w.Header().Get(hdrAmzRequestID)
}

// GetWriterStatus returns the status code already sent to the client by w.
func GetWriterStatus(w http.ResponseWriter) int {
	if sw, ok := w.(writerStatus); ok {
		return sw.Status()
	}

	return 0
}

// NewRouter creates the router to serve the S3 API with.
func NewRouter() *mux.Router {
	return mux.NewRouter().SkipClean(true)
}

// Attach adds S3 API handlers from h to r for domains with m client limit using
// center authentication and log logger.
func Attach(r *mux.Router, domains []string, m MaxClients, h Handler, center auth.Center, log *zap.Logger) {
	api := r.PathPrefix(SlashSeparator).Subrouter()

	api.Use(
		// -- prepare request
		setRequestID,

		// -- logging error requests
		logErrorResponse(log),

		appendPreflight(h),
	)

	// Attach user authentication for all S3 routes.
	AttachUserAuth(api, center, log)

	// Count request bodies after authentication unwrapped them.
	api.Use(countBody)

	buckets := make([]*mux.Router, 0, len(domains)+1)
	buckets = append(buckets, api.PathPrefix("/{bucket}").Subrouter())

	for _, domain := range domains {
		buckets = append(buckets, api.Host("{bucket:.+}."+domain).Subrouter())
	}

	for _, bucket := range buckets {
		// Object operations
		// HeadObject
		bucket.Use(
			// -- append CORS headers to a response for
			appendCORS(h),
		)
		bucket.Methods(http.MethodOptions).HandlerFunc(m.Handle(metrics.APIStats("preflight", h.Preflight))).Name("Options")
		bucket.Methods(http.MethodHead).Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("headobject", h.HeadObjectHandler))).Name("HeadObject")
		// CopyObjectPart
		bucket.Methods(http.MethodPut).Headers(hdrAmzCopySource, "").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}").Path("/{object:(?s).+}").HandlerFunc(m.Handle(metrics.APIStats("uploadpartcopy", h.UploadPartCopy))).
			Name("UploadPartCopy")
		// PutObjectPart
		bucket.Methods(http.MethodPut).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("uploadpart", h.UploadPartHandler))).
			Name("UploadPart")
		// ListParts
		bucket.Methods(http.MethodGet).Queries("uploadId", "{uploadId:.*}").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("listobjectparts", h.ListPartsHandler))).
			Name("ListObjectParts")
		// CompleteMultipartUpload
		bucket.Methods(http.MethodPost).Queries("uploadId", "{uploadId:.*}").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("completemutipartupload", h.CompleteMultipartUploadHandler))).
			Name("CompleteMultipartUpload")
		// CreateMultipartUpload
		bucket.Methods(http.MethodPost).Queries("uploads", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("createmultipartupload", h.CreateMultipartUploadHandler))).
			Name("CreateMultipartUpload")
		// AbortMultipartUpload
		bucket.Methods(http.MethodDelete).Queries("uploadId", "{uploadId:.*}").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("abortmultipartupload", h.AbortMultipartUploadHandler))).
			Name("AbortMultipartUpload")
		// ListMultipartUploads
		bucket.Methods(http.MethodGet).Queries("uploads", "").HandlerFunc(
			m.Handle(metrics.APIStats("listmultipartuploads", h.ListMultipartUploadsHandler))).
			Name("ListMultipartUploads")
		// GetObjectACL -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("acl", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobjectacl", h.GetObjectACLHandler))).
			Name("GetObjectACL")
		// PutObjectACL -- this is a dummy call.
		bucket.Methods(http.MethodPut).Queries("acl", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("putobjectacl", h.PutObjectACLHandler))).
			Name("PutObjectACL")
		// GetObjectTagging
		bucket.Methods(http.MethodGet).Queries("tagging", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobjecttagging", h.GetObjectTaggingHandler))).
			Name("GetObjectTagging")
		// PutObjectTagging
		bucket.Methods(http.MethodPut).Queries("tagging", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("putobjecttagging", h.PutObjectTaggingHandler))).
			Name("PutObjectTagging")
		// DeleteObjectTagging
		bucket.Methods(http.MethodDelete).Queries("tagging", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("deleteobjecttagging", h.DeleteObjectTaggingHandler))).
			Name("DeleteObjectTagging")
		// SelectObjectContent
		bucket.Methods(http.MethodPost).Queries("select", "").Queries("select-type", "2").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("selectobjectcontent", h.SelectObjectContentHandler))).
			Name("SelectObjectContent")
		// GetObjectRetention
		bucket.Methods(http.MethodGet).Queries("retention", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobjectretention", h.GetObjectRetentionHandler))).
			Name("GetObjectRetention")
		// GetObjectLegalHold
		bucket.Methods(http.MethodGet).Queries("legal-hold", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobjectlegalhold", h.GetObjectLegalHoldHandler))).
			Name("GetObjectLegalHold")
		// GetObjectAttributes
		bucket.Methods(http.MethodGet).Queries("attributes", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobjectattributes", h.GetObjectAttributesHandler))).
			Name("GetObjectAttributes")
		// GetObjectTorrentHandler
		bucket.Methods(http.MethodGet).Queries("torrent", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobjecttorrent", h.GetObjectTorrentHandler))).
			Name("GetObjectTorrent")
		// GetObject
		bucket.Methods(http.MethodGet).Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("getobject", h.GetObjectHandler))).
			Name("GetObject")
		// CopyObject
		bucket.Methods(http.MethodPut).Headers(hdrAmzCopySource, "").Path("/{object:(?s).+}").HandlerFunc(m.Handle(metrics.APIStats("copyobject", h.CopyObjectHandler))).
			Name("CopyObject")
		// PutObjectRetention
		bucket.Methods(http.MethodPut).Queries("retention", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("putobjectretention", h.PutObjectRetentionHandler))).
			Name("PutObjectRetention")
		// PutObjectLegalHold
		bucket.Methods(http.MethodPut).Queries("legal-hold", "").Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("putobjectlegalhold", h.PutObjectLegalHoldHandler))).
			Name("PutObjectLegalHold")

		// PutObject
		bucket.Methods(http.MethodPut).Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("putobject", h.PutObjectHandler))).
			Name("PutObject")
		// DeleteObject
		bucket.Methods(http.MethodDelete).Path("/{object:(?s).+}").HandlerFunc(
			m.Handle(metrics.APIStats("deleteobject", h.DeleteObjectHandler))).
			Name("DeleteObject")

		// Bucket operations
		// GetBucketLocation
		bucket.Methods(http.MethodGet).Queries("location", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketlocation", h.GetBucketLocationHandler))).
			Name("GetBucketLocation")
		// GetBucketPolicy
		bucket.Methods(http.MethodGet).Queries("policy", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketpolicy", h.GetBucketPolicyHandler))).
			Name("GetBucketPolicy")
		// GetBucketLifecycle
		bucket.Methods(http.MethodGet).Queries("lifecycle", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketlifecycle", h.GetBucketLifecycleHandler))).
			Name("GetBucketLifecycle")
		// GetBucketEncryption
		bucket.Methods(http.MethodGet).Queries("encryption", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketencryption", h.GetBucketEncryptionHandler))).
			Name("GetBucketEncryption")
		bucket.Methods(http.MethodGet).Queries("cors", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketcors", h.GetBucketCorsHandler))).
			Name("GetBucketCors")
		bucket.Methods(http.MethodPut).Queries("cors", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketcors", h.PutBucketCorsHandler))).
			Name("PutBucketCors")
		bucket.Methods(http.MethodDelete).Queries("cors", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebucketcors", h.DeleteBucketCorsHandler))).
			Name("DeleteBucketCors")
		// Dummy Bucket Calls
		// GetBucketACL -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("acl", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketacl", h.GetBucketACLHandler))).
			Name("GetBucketACL")
		// PutBucketACL -- this is a dummy call.
		bucket.Methods(http.MethodPut).Queries("acl", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketacl", h.PutBucketACLHandler))).
			Name("PutBucketACL")
		// GetBucketWebsiteHandler -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("website", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketwebsite", h.GetBucketWebsiteHandler))).
			Name("GetBucketWebsite")
		// GetBucketAccelerateHandler -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("accelerate", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketaccelerate", h.GetBucketAccelerateHandler))).
			Name("GetBucketAccelerate")
		// GetBucketRequestPaymentHandler -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("requestPayment", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketrequestpayment", h.GetBucketRequestPaymentHandler))).
			Name("GetBucketRequestPayment")
		// GetBucketLoggingHandler -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("logging", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketlogging", h.GetBucketLoggingHandler))).
			Name("GetBucketLogging")
		// PutBucketLoggingHandler -- this is a dummy call.
		bucket.Methods(http.MethodPut).Queries("logging", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketlogging", h.PutBucketLoggingHandler))).
			Name("PutBucketLogging")
		// GetBucketLifecycleHandler -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("lifecycle", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketlifecycle", h.GetBucketLifecycleHandler))).
			Name("GetBucketLifecycle")
		// GetBucketReplicationHandler -- this is a dummy call.
		bucket.Methods(http.MethodGet).Queries("replication", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketreplication", h.GetBucketReplicationHandler))).
			Name("GetBucketReplication")
		// GetBucketTaggingHandler
		bucket.Methods(http.MethodGet).Queries("tagging", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbuckettagging", h.GetBucketTaggingHandler))).
			Name("GetBucketTagging")
		// DeleteBucketWebsiteHandler
		bucket.Methods(http.MethodDelete).Queries("website", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebucketwebsite", h.DeleteBucketWebsiteHandler))).
			Name("DeleteBucketWebsite")
		// DeleteBucketTaggingHandler
		bucket.Methods(http.MethodDelete).Queries("tagging", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebuckettagging", h.DeleteBucketTaggingHandler))).
			Name("DeleteBucketTagging")

		// GetBucketObjectLockConfig
		bucket.Methods(http.MethodGet).Queries("object-lock", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketobjectlockconfiguration", h.GetBucketObjectLockConfigHandler))).
			Name("GetBucketObjectLockConfig")
		// GetBucketVersioning
		bucket.Methods(http.MethodGet).Queries("versioning", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketversioning", h.GetBucketVersioningHandler))).
			Name("GetBucketVersioning")
		// GetBucketNotification
		bucket.Methods(http.MethodGet).Queries("notification", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketnotification", h.GetBucketNotificationHandler))).
			Name("GetBucketNotification")
		// ListenBucketNotification
		bucket.Methods(http.MethodGet).Queries("events", "{events:.*}").HandlerFunc(metrics.APIStats("listenbucketnotification", h.ListenBucketNotificationHandler)).
			Name("ListenBucketNotification")
		// ListObjectsV2M
		bucket.Methods(http.MethodGet).Queries("list-type", "2", "metadata", "true").HandlerFunc(
			m.Handle(metrics.APIStats("listobjectsv2M", h.ListObjectsV2MHandler))).
			Name("ListObjectsV2M")
		// ListObjectsV2
		bucket.Methods(http.MethodGet).Queries("list-type", "2").HandlerFunc(
			m.Handle(metrics.APIStats("listobjectsv2", h.ListObjectsV2Handler))).
			Name("ListObjectsV2")
		// ListBucketVersions
		bucket.Methods(http.MethodGet).Queries("versions", "").HandlerFunc(
			m.Handle(metrics.APIStats("listbucketversions", h.ListBucketObjectVersionsHandler))).
			Name("ListBucketVersions")
		// GetBucketPolicyStatus
		bucket.Methods(http.MethodGet).Queries("policyStatus", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketpolicystatus", h.GetBucketPolicyStatusHandler))).
			Name("GetBucketPolicyStatus")
		// PutPublicAccessBlock
		bucket.Methods(http.MethodPut).Queries("publicAccessBlock", "").HandlerFunc(
			m.Handle(metrics.APIStats("putpublicaccessblock", h.PutPublicAccessBlockHandler))).
			Name("PutPublicAccessBlock")
		// GetPublicAccessBlock
		bucket.Methods(http.MethodGet).Queries("publicAccessBlock", "").HandlerFunc(
			m.Handle(metrics.APIStats("getpublicaccessblock", h.GetPublicAccessBlockHandler))).
			Name("GetPublicAccessBlock")
		// GetBucketOwnershipControls
		bucket.Methods(http.MethodGet).Queries("ownershipControls", "").HandlerFunc(
			m.Handle(metrics.APIStats("getbucketownershipcontrols", h.GetBucketOwnershipControlsHandler))).
			Name("GetBucketOwnershipControls")
		// ListObjectsV1 (Legacy)
		bucket.Methods(http.MethodGet).HandlerFunc(
			m.Handle(metrics.APIStats("listobjectsv1", h.ListObjectsV1Handler))).
			Name("ListObjectsV1")
		// PutBucketLifecycle
		bucket.Methods(http.MethodPut).Queries("lifecycle", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketlifecycle", h.PutBucketLifecycleHandler))).
			Name("PutBucketLifecycle")
		// PutBucketEncryption
		bucket.Methods(http.MethodPut).Queries("encryption", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketencryption", h.PutBucketEncryptionHandler))).
			Name("PutBucketEncryption")

		// PutBucketPolicy
		bucket.Methods(http.MethodPut).Queries("policy", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketpolicy", h.PutBucketPolicyHandler))).
			Name("PutBucketPolicy")

		// PutBucketObjectLockConfig
		bucket.Methods(http.MethodPut).Queries("object-lock", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketobjectlockconfig", h.PutBucketObjectLockConfigHandler))).
			Name("PutBucketObjectLockConfig")
		// PutBucketTaggingHandler
		bucket.Methods(http.MethodPut).Queries("tagging", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbuckettagging", h.PutBucketTaggingHandler))).
			Name("PutBucketTagging")
		// PutBucketVersioning
		bucket.Methods(http.MethodPut).Queries("versioning", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketversioning", h.PutBucketVersioningHandler))).
			Name("PutBucketVersioning")
		// PutBucketNotification
		bucket.Methods(http.MethodPut).Queries("notification", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketnotification", h.PutBucketNotificationHandler))).
			Name("PutBucketNotification")
		// PutBucketOwnershipControls
		bucket.Methods(http.MethodPut).Queries("ownershipControls", "").HandlerFunc(
			m.Handle(metrics.APIStats("putbucketownershipcontrols", h.PutBucketOwnershipControlsHandler))).
			Name("PutBucketOwnershipControls")
		// DeleteBucketOwnershipControls
		bucket.Methods(http.MethodDelete).Queries("ownershipControls", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebucketownershipcontrols", h.DeleteBucketOwnershipControlsHandler))).
			Name("DeleteBucketOwnershipControls")
		// CreateBucket
		bucket.Methods(http.MethodPut).HandlerFunc(
			m.Handle(metrics.APIStats("createbucket", h.CreateBucketHandler))).
			Name("CreateBucket")
		// HeadBucket
		bucket.Methods(http.MethodHead).HandlerFunc(
			m.Handle(metrics.APIStats("headbucket", h.HeadBucketHandler))).
			Name("HeadBucket")
		// PostPolicy
		bucket.Methods(http.MethodPost).HeadersRegexp(hdrContentType, "multipart/form-data*").HandlerFunc(
			m.Handle(metrics.APIStats("postobject", h.PostObject))).
			Name("PostObject")
		// DeleteMultipleObjects
		bucket.Methods(http.MethodPost).Queries("delete", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletemultipleobjects", h.DeleteMultipleObjectsHandler))).
			Name("DeleteMultipleObjects")
		// DeleteBucketPolicy
		bucket.Methods(http.MethodDelete).Queries("policy", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebucketpolicy", h.DeleteBucketPolicyHandler))).
			Name("DeleteBucketPolicy")
		// DeleteBucketLifecycle
		bucket.Methods(http.MethodDelete).Queries("lifecycle", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebucketlifecycle", h.DeleteBucketLifecycleHandler))).
			Name("DeleteBucketLifecycle")
		// DeleteBucketEncryption
		bucket.Methods(http.MethodDelete).Queries("encryption", "").HandlerFunc(
			m.Handle(metrics.APIStats("deletebucketencryption", h.DeleteBucketEncryptionHandler))).
			Name("DeleteBucketEncryption")
		// DeleteBucket
		bucket.Methods(http.MethodDelete).HandlerFunc(
			m.Handle(metrics.APIStats("deletebucket", h.DeleteBucketHandler))).
			Name("DeleteBucket")
	}
	// Root operation

	// ListBuckets
	api.Methods(http.MethodGet).Path(SlashSeparator).HandlerFunc(
		m.Handle(metrics.APIStats("listbuckets", h.ListBucketsHandler))).
		Name("ListBuckets")

	// S3 browser with signature v4 adds '//' for ListBuckets request, so rather
	// than failing with UnknownAPIRequest we simply handle it for now.
	api.Methods(http.MethodGet).Path(SlashSeparator + SlashSeparator).HandlerFunc(
		m.Handle(metrics.APIStats("listbuckets", h.ListBucketsHandler))).
		Name("ListBuckets")

	// If none of the routes match, add default error handler routes
	api.NotFoundHandler = metrics.APIStats("notfound", errorResponseHandler)
	api.MethodNotAllowedHandler = metrics.APIStats("methodnotallowed", errorResponseHandler)
}
