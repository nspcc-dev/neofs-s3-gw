package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gw/api/auth"
	"go.uber.org/zap"
)

type stubHandler struct {
	Handler
}

func (stubHandler) GetObjectHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) ListObjectsV2Handler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) HeadObjectHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) Preflight(http.ResponseWriter, *http.Request)         {}
func (stubHandler) AppendCORSHeaders(http.ResponseWriter, *http.Request) {}

type stubCenter struct{}

func (stubCenter) Authenticate(*http.Request) (*auth.Box, error) {
	return nil, auth.ErrNoAuthorizationHeader
}

func newBenchRouter() *mux.Router {
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	Attach(router, nil, NewMaxClientsMiddleware(100, time.Second), stubHandler{}, stubCenter{}, zap.NewNop())
	return router
}

func benchmarkRoute(b *testing.B, method, target string) {
	b.Helper()

	router := newBenchRouter()
	req := httptest.NewRequest(method, target, nil)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}

func BenchmarkRouterGetObject(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket/some/object/key")
}

func BenchmarkRouterListObjectsV2(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket?list-type=2&prefix=some/prefix&max-keys=1000")
}

func BenchmarkRouterHeadObject(b *testing.B) {
	benchmarkRoute(b, http.MethodHead, "/bucket/some/object/key")
}
