package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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
