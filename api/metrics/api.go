package metrics

import (
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type (
	// HTTPStats holds statistics information about
	// HTTP requests made by all clients.
	HTTPStats struct {
		currentS3Requests map[string]*atomic.Uint64
		totalS3Requests   map[string]*atomic.Uint64
		totalS3Errors     map[string]*atomic.Uint64

		totalInputBytes  atomic.Uint64
		totalOutputBytes atomic.Uint64
	}

	readCounter struct {
		io.ReadCloser
		countBytes uint64
	}

	writeCounter struct {
		http.ResponseWriter
		countBytes uint64
	}

	responseWrapper struct {
		sync.Once
		http.ResponseWriter

		statusCode int
		startTime  time.Time
	}
)

const systemPath = "/system"

var (
	httpStatsMetric = &HTTPStats{
		currentS3Requests: make(map[string]*atomic.Uint64),
		totalS3Requests:   make(map[string]*atomic.Uint64),
		totalS3Errors:     make(map[string]*atomic.Uint64),
	}
	httpRequestsDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "neofs_s3_request_seconds",
			Help:    "Time taken by requests served by current NeoFS S3 Gate instance",
			Buckets: []float64{.05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"api"},
	)
)

// Collects HTTP metrics for NeoFS S3 Gate in Prometheus specific format
// and sends to the given channel.
func collectHTTPMetrics(ch chan<- prometheus.Metric) {
	for api, value := range httpStatsMetric.currentS3Requests {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, "requests", "current"),
				"Total number of running s3 requests in current NeoFS S3 Gate instance",
				[]string{"api"}, nil),
			prometheus.CounterValue,
			float64(value.Load()),
			api,
		)
	}

	for api, value := range httpStatsMetric.totalS3Requests {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, "requests", "total"),
				"Total number of s3 requests in current NeoFS S3 Gate instance",
				[]string{"api"}, nil),
			prometheus.CounterValue,
			float64(value.Load()),
			api,
		)
	}

	for api, value := range httpStatsMetric.totalS3Errors {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(namespace, "errors", "total"),
				"Total number of s3 errors in current NeoFS S3 Gate instance",
				[]string{"api"}, nil),
			prometheus.CounterValue,
			float64(value.Load()),
			api,
		)
	}
}

// APIStats wraps http handler for api with basic statistics collection.
func APIStats(api string, f http.HandlerFunc) http.HandlerFunc {
	httpStatsMetric.currentS3Requests[api] = new(atomic.Uint64)
	httpStatsMetric.totalS3Requests[api] = new(atomic.Uint64)
	httpStatsMetric.totalS3Errors[api] = new(atomic.Uint64)

	return func(w http.ResponseWriter, r *http.Request) {
		httpStatsMetric.currentS3Requests[api].Add(1)
		defer httpStatsMetric.currentS3Requests[api].Add(math.MaxUint64)

		in := &readCounter{ReadCloser: r.Body}
		out := &writeCounter{ResponseWriter: w}

		r.Body = in

		statsWriter := &responseWrapper{
			ResponseWriter: out,
			startTime:      time.Now(),
		}

		f.ServeHTTP(statsWriter, r)

		// Time duration in secs since the call started.
		// We don't need to do nanosecond precision here
		// simply for the fact that it is not human readable.
		durationSecs := time.Since(statsWriter.startTime).Seconds()

		httpStatsMetric.updateStats(api, statsWriter, r, durationSecs)

		httpStatsMetric.totalInputBytes.Add(in.countBytes)
		httpStatsMetric.totalOutputBytes.Add(out.countBytes)
	}
}

func (st *HTTPStats) getInputBytes() uint64 {
	return st.totalInputBytes.Load()
}

func (st *HTTPStats) getOutputBytes() uint64 {
	return st.totalOutputBytes.Load()
}

// Update statistics from http request and response data.
func (st *HTTPStats) updateStats(api string, w http.ResponseWriter, r *http.Request, durationSecs float64) {
	var code int

	if res, ok := w.(*responseWrapper); ok {
		code = res.statusCode
	}

	// A successful request has a 2xx response code
	successReq := code >= http.StatusOK && code < http.StatusMultipleChoices

	if !strings.HasSuffix(r.URL.Path, systemPath) {
		st.totalS3Requests[api].Add(1)
		if !successReq && code != 0 {
			st.totalS3Errors[api].Add(1)
		}
	}

	// Increment the prometheus http request response histogram with appropriate label
	httpRequestsDuration.With(prometheus.Labels{"api": api}).Observe(durationSecs)
}

// WriteHeader -- writes http status code.
func (w *responseWrapper) WriteHeader(code int) {
	w.Do(func() {
		w.statusCode = code
		w.ResponseWriter.WriteHeader(code)
	})
}

// Flush -- calls the underlying Flush.
func (w *responseWrapper) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *writeCounter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	atomic.AddUint64(&w.countBytes, uint64(n))
	return n, err
}

func (r *readCounter) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	atomic.AddUint64(&r.countBytes, uint64(n))
	return n, err
}
