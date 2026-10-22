package api

import (
	"context"
	"net/http"
	"strings"
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

func setRequestID(domains []string) mux.MiddlewareFunc {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// generate random UUIDv4
			id, _ := uuid.NewRandom()

			// set request id into response header
			w.Header().Set(hdrAmzRequestID, id.String())

			// set request id into gRPC meta header
			ctx := metadata.AppendToOutgoingContext(r.Context(), hdrAmzRequestID, id.String())

			// set request info into context
			ctx = prepareContext(ctx, w, r, domains) //nolint:contextcheck // In fact, r.Context() is reused internally

			// continue execution
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requestTarget returns the bucket and the object addressed by r, path-style (/bucket/object)
// first, then virtual-hosted-style (bucket.domain/object) for one of domains. Both are empty
// for requests to the service itself.
func requestTarget(r *http.Request, domains []string) (bucket, object string) {
	path := r.URL.Path
	if len(path) > 1 && path[0] == '/' && path[1] != '/' {
		bucket, object, _ = strings.Cut(path[1:], "/")
		return bucket, object
	}

	host := r.Host
	if r.URL.IsAbs() {
		host = r.URL.Host
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}

	for _, domain := range domains {
		if i := len(host) - len(domain) - 1; i > 0 && host[i] == '.' && host[i+1:] == domain {
			object, _ = strings.CutPrefix(path, "/")
			return host[:i], object
		}
	}

	return "", ""
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
				zap.String("method", reqInfo.API),
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
	r.Use(
		// -- prepare request
		setRequestID(domains),

		// -- logging error requests
		logErrorResponse(log),

		appendPreflight(h),
	)

	// Attach user authentication for all S3 routes.
	AttachUserAuth(r, center, log)

	var handlers = make(map[string]http.HandlerFunc, len(operations)+1)
	for i := range operations {
		var (
			op = &operations[i]
			f  = metrics.APIStats(op.metric, func(w http.ResponseWriter, r *http.Request) { op.handler(h, w, r) })
		)

		if !op.unlimited {
			f = m.Handle(f)
		}

		handlers[op.name] = f
	}
	handlers[listBucketsOperation] = m.Handle(metrics.APIStats("listbuckets", h.ListBucketsHandler))

	var (
		notFound = metrics.APIStats("notfound", errorResponseHandler)
		// The operation was resolved while preparing the request info (see prepareContext), the
		// routes below only distinguish object and bucket paths per method.
		dispatch = func(w http.ResponseWriter, r *http.Request) {
			if f, ok := handlers[GetReqInfo(r.Context()).API]; ok {
				f(w, r)
				return
			}

			notFound(w, r)
		}
	)

	var (
		// bucket and object responses get CORS headers
		bucketDispatch = appendCORS(h)(http.HandlerFunc(dispatch))

		isObject = func(r *http.Request, _ *mux.RouteMatch) bool {
			_, object := requestTarget(r, domains)
			return object != ""
		}
		isBucket = func(r *http.Request, _ *mux.RouteMatch) bool {
			bucket, _ := requestTarget(r, domains)
			return bucket != ""
		}
		isService = func(r *http.Request, _ *mux.RouteMatch) bool {
			return r.URL.Path == SlashSeparator || r.URL.Path == SlashSeparator+SlashSeparator
		}
	)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPost, http.MethodDelete} {
		r.Methods(method).MatcherFunc(isObject).Handler(bucketDispatch).Name("Object" + method)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions} {
		r.Methods(method).MatcherFunc(isBucket).Handler(bucketDispatch).Name("Bucket" + method)
	}

	// ListBuckets
	r.Methods(http.MethodGet).MatcherFunc(isService).HandlerFunc(dispatch).Name(listBucketsOperation)

	r.NotFoundHandler = notFound
	r.MethodNotAllowedHandler = metrics.APIStats("methodnotallowed", errorResponseHandler)
}
