package api

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type (
	captureHandler struct {
		Handler

		route  string
		bucket string
		object string
	}

	stubCenter struct{}
)

func (h *captureHandler) capture(w http.ResponseWriter, r *http.Request) {
	info := GetReqInfo(r.Context())
	h.route, h.bucket, h.object = info.API, info.BucketName, info.ObjectName
	w.WriteHeader(http.StatusOK)
}

func (h *captureHandler) GetObjectHandler(w http.ResponseWriter, r *http.Request)  { h.capture(w, r) }
func (h *captureHandler) HeadObjectHandler(w http.ResponseWriter, r *http.Request) { h.capture(w, r) }
func (h *captureHandler) PutObjectHandler(w http.ResponseWriter, r *http.Request)  { h.capture(w, r) }
func (h *captureHandler) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) ListObjectsV1Handler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) ListObjectsV2Handler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) CreateBucketHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) UploadPartHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) CopyObjectHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) Preflight(http.ResponseWriter, *http.Request)         {}
func (h *captureHandler) AppendCORSHeaders(http.ResponseWriter, *http.Request) {}

func (stubCenter) Authenticate(*http.Request) (*auth.Box, error) {
	return nil, auth.ErrNoAuthorizationHeader
}

func newTestRouter(h Handler) *mux.Router {
	router := NewRouter()
	Attach(router, []string{"s3.test"}, NewMaxClientsMiddleware(100, time.Second), h, stubCenter{}, zap.NewNop())
	return router
}

func TestRouterObjectKeys(t *testing.T) {
	for _, key := range []string{
		"some/object/key",
		"plain.txt",
		"with space/and more.txt",
		"with+plus.txt",
		"with%percent.txt",
		// decoded forms that are themselves valid escape sequences: unescaping
		// the routed key a second time would silently corrupt these
		"percent%2Fencoded.txt",
		"100%20off.txt",
		"with?question.txt",
		"with&ampersand.txt",
		"with#hash.txt",
		"with=equals.txt",
		"with:colon.txt",
		"with[brackets].txt",
		"кириллица/файл.txt",
		"emoji/🙂.txt",
		"trailing/slash/",
		"double//slash.txt",
		"with\nnewline.txt",
		"with\ttab.txt",
	} {
		t.Run(key, func(t *testing.T) {
			h := &captureHandler{}
			router := newTestRouter(h)

			// encode exactly like a client would
			target := (&url.URL{Path: "/bucket/" + key}).RequestURI()

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

			require.Equal(t, http.StatusOK, rec.Code, "target %q", target)
			require.Equal(t, "GetObject", h.route)
			require.Equal(t, "bucket", h.bucket)
			require.Equal(t, key, h.object)
		})
	}
}

func TestRouterEncodedSlash(t *testing.T) {
	for _, target := range []string{"/bucket/a%2Fb", "/bucket/a/b"} {
		t.Run(target, func(t *testing.T) {
			h := &captureHandler{}
			rec := httptest.NewRecorder()
			newTestRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, "a/b", h.object)
		})
	}
}

type failingHandler struct {
	Handler
}

// GetObjectHandler commits 200 with the payload and only then fails, just like
// the real one does when object reading breaks in the middle.
func (h *failingHandler) GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	WriteErrorResponse(w, GetReqInfo(r.Context()), s3errors.GetAPIError(s3errors.ErrInternalError))
}
func (h *failingHandler) Preflight(http.ResponseWriter, *http.Request)         {}
func (h *failingHandler) AppendCORSHeaders(http.ResponseWriter, *http.Request) {}

func TestRouterFailureAfterHeader(t *testing.T) {
	var (
		core, logs = observer.New(zapcore.InfoLevel)
		router     = NewRouter()
	)

	Attach(router, []string{"s3.test"}, NewMaxClientsMiddleware(100, time.Second), &failingHandler{}, stubCenter{}, zap.New(core))

	var rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bucket/object", nil))

	// the client still gets 200
	require.Equal(t, http.StatusOK, rec.Code)

	// but the request has failed, so the router must not report a result of
	// its own, the handler owns that record (see TestLogAndSendError)
	require.Empty(t, logs.FilterMessage("call method result").All())
}

func (h *captureHandler) GetObjectACLHandler(w http.ResponseWriter, r *http.Request) { h.capture(w, r) }
func (h *captureHandler) ListPartsHandler(w http.ResponseWriter, r *http.Request)    { h.capture(w, r) }
func (h *captureHandler) UploadPartCopy(w http.ResponseWriter, r *http.Request)      { h.capture(w, r) }
func (h *captureHandler) HeadBucketHandler(w http.ResponseWriter, r *http.Request)   { h.capture(w, r) }
func (h *captureHandler) PostObject(w http.ResponseWriter, r *http.Request)          { h.capture(w, r) }
func (h *captureHandler) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) SelectObjectContentHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) ListObjectsV2MHandler(w http.ResponseWriter, r *http.Request) {
	h.capture(w, r)
}
func (h *captureHandler) GetBucketACLHandler(w http.ResponseWriter, r *http.Request) { h.capture(w, r) }

func TestRouterOperationPrecedence(t *testing.T) {
	copySource := http.Header{hdrAmzCopySource: {"bucket/other"}}
	formData := http.Header{hdrContentType: {"multipart/form-data; boundary=x"}}

	for _, tc := range []struct {
		method, target string
		header         http.Header
		route, bucket  string
		object         string
		status         int
	}{
		{method: http.MethodGet, target: "/", route: "ListBuckets"},
		{method: http.MethodGet, target: "//", route: "ListBuckets"},
		{method: http.MethodGet, target: "/bucket", route: "ListObjectsV1", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket/", route: "ListObjectsV1", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket?list-type=2", route: "ListObjectsV2", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket?list-type=2&metadata=true", route: "ListObjectsV2M", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket?list-type=1", route: "ListObjectsV1", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket?location", route: "GetBucketLocation", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket?acl&tagging", route: "GetBucketACL", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket?uploads", route: "ListMultipartUploads", bucket: "bucket"},
		{method: http.MethodHead, target: "/bucket", route: "HeadBucket", bucket: "bucket"},
		{method: http.MethodPut, target: "/bucket", route: "CreateBucket", bucket: "bucket"},
		{method: http.MethodGet, target: "/bucket/key", route: "GetObject", bucket: "bucket", object: "key"},
		{method: http.MethodGet, target: "/bucket/key?location", route: "GetObject", bucket: "bucket", object: "key"},
		{method: http.MethodGet, target: "/bucket/key?acl=private", route: "GetObjectACL", bucket: "bucket", object: "key"},
		{method: http.MethodGet, target: "/bucket/key?tagging", route: "GetObjectTagging", bucket: "bucket", object: "key"},
		{method: http.MethodGet, target: "/bucket/key?uploadId=1", route: "ListObjectParts", bucket: "bucket", object: "key"},
		{method: http.MethodGet, target: "/bucket/key?uploads", route: "ListMultipartUploads", bucket: "bucket"},
		{method: http.MethodHead, target: "/bucket/key", route: "HeadObject", bucket: "bucket", object: "key"},
		{method: http.MethodPut, target: "/bucket/key", route: "PutObject", bucket: "bucket", object: "key"},
		{method: http.MethodPut, target: "/bucket/key?cors", route: "PutObject", bucket: "bucket", object: "key"},
		{method: http.MethodPut, target: "/bucket/key?partNumber=1&uploadId=u", route: "UploadPart", bucket: "bucket", object: "key"},
		{method: http.MethodPut, target: "/bucket/key?partNumber=x&uploadId=u", route: "PutObject", bucket: "bucket", object: "key"},
		{method: http.MethodPut, target: "/bucket/key?partNumber=1&uploadId=u", header: copySource, route: "UploadPartCopy", bucket: "bucket", object: "key"},
		{method: http.MethodPut, target: "/bucket/key", header: copySource, route: "CopyObject", bucket: "bucket", object: "key"},
		{method: http.MethodPost, target: "/bucket/key?select&select-type=2", route: "SelectObjectContent", bucket: "bucket", object: "key"},
		{method: http.MethodPost, target: "/bucket/key?select&select-type=1", bucket: "bucket", object: "key", status: http.StatusBadRequest},
		{method: http.MethodPost, target: "/bucket/key?delete", route: "DeleteMultipleObjects", bucket: "bucket"},
		{method: http.MethodPost, target: "/bucket?delete", route: "DeleteMultipleObjects", bucket: "bucket"},
		{method: http.MethodPost, target: "/bucket", header: formData, route: "PostObject", bucket: "bucket"},
		{method: http.MethodPost, target: "/bucket", bucket: "bucket", status: http.StatusBadRequest},
	} {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			h := &captureHandler{}
			req := httptest.NewRequest(tc.method, tc.target, nil)
			maps.Copy(req.Header, tc.header)
			rec := httptest.NewRecorder()
			newTestRouter(h).ServeHTTP(rec, req)

			if tc.status != 0 {
				require.Equal(t, tc.status, rec.Code)
				require.Empty(t, h.route)
				return
			}
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, tc.route, h.route)
			require.Equal(t, tc.bucket, h.bucket)
			require.Equal(t, tc.object, h.object)
		})
	}
}

func TestRouterRequestTarget(t *testing.T) {
	for _, tc := range []struct {
		method, host, target string
		route, bucket        string
		object               string
		status               int
	}{
		{method: http.MethodGet, host: "bucket.s3.test", target: "//key", route: "GetObject", bucket: "bucket", object: "/key"},
		{method: http.MethodGet, host: "bucket.s3.test", target: "/", route: "ListObjectsV1", bucket: "bucket"},
		{method: http.MethodGet, host: "bucket.s3.test", target: "//", route: "GetObject", bucket: "bucket", object: "/"},
		{method: http.MethodHead, host: "bucket.s3.test", target: "/", route: "HeadBucket", bucket: "bucket"},
		{method: http.MethodGet, host: "bucket.s3.test:8080", target: "/", route: "ListObjectsV1", bucket: "bucket"},
		{method: http.MethodGet, host: "bucket.s3.test", target: "http://bucket.s3.test/", route: "ListObjectsV1", bucket: "bucket"},
		{method: http.MethodGet, host: "a.b.s3.test", target: "/", route: "ListObjectsV1", bucket: "a.b"},
		{method: http.MethodGet, host: "s3.test", target: "/", route: "ListBuckets"},
		{method: http.MethodGet, host: ".s3.test", target: "/", route: "ListBuckets"},
		{method: http.MethodGet, host: "buckets3.test", target: "/", route: "ListBuckets"},
		{method: http.MethodGet, host: "bucket.other.test", target: "/", route: "ListBuckets"},
		{method: http.MethodGet, host: "host.s3.test", target: "/bucket/key", route: "GetObject", bucket: "bucket", object: "key"},
		{method: http.MethodGet, host: "example.com", target: "//key", status: http.StatusBadRequest},
		{method: http.MethodPut, host: "example.com", target: "/", status: http.StatusBadRequest},
		{method: http.MethodPatch, host: "example.com", target: "/bucket/key", status: http.StatusBadRequest},
		{method: http.MethodPatch, host: "bucket.s3.test", target: "/", status: http.StatusBadRequest},
	} {
		t.Run(tc.method+" "+tc.host+" "+tc.target, func(t *testing.T) {
			h := &captureHandler{}
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			newTestRouter(h).ServeHTTP(rec, req)

			if tc.status != 0 {
				require.Equal(t, tc.status, rec.Code)
				require.Empty(t, h.route)
				return
			}
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, tc.route, h.route)
			require.Equal(t, tc.bucket, h.bucket)
			require.Equal(t, tc.object, h.object)
		})
	}
}
