package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

type stubHandler struct {
	Handler
}

func (stubHandler) GetObjectHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) HeadObjectHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) ListObjectsV1Handler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) GetObjectTaggingHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
func (stubHandler) Preflight(http.ResponseWriter, *http.Request)         {}
func (stubHandler) AppendCORSHeaders(http.ResponseWriter, *http.Request) {}

func newBenchRouter() *mux.Router {
	router := NewRouter()
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

func BenchmarkRouterHeadObject(b *testing.B) {
	benchmarkRoute(b, http.MethodHead, "/bucket/some/object/key")
}

func BenchmarkRouterHeadObjectEscapedPath(b *testing.B) {
	benchmarkRoute(b, http.MethodHead, "/bucket/some%20object/key%20name")
}

func BenchmarkRouterGetObjectTagging(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket/some/object/key?tagging=")
}

func BenchmarkRouterGetObjectTaggingEscapedPath(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket/some%20object/key%20name?tagging=")
}

func BenchmarkRouterGetObject(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket/some/object/key")
}

func BenchmarkRouterGetObjectEscapedPath(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket/some%20object/key%20name")
}

func BenchmarkRouterListObjectsV1(b *testing.B) {
	benchmarkRoute(b, http.MethodGet, "/bucket?prefix=some/prefix&max-keys=1000")
}
