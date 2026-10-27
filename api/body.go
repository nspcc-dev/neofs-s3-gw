package api

import (
	"errors"
	"io"
	"net/http"
	"sync/atomic"

	"github.com/nspcc-dev/neofs-s3-gw/api/metrics"
)

type (
	bodyReader struct {
		io.ReadCloser
		countBytes atomic.Uint64
		// expected is the body length to enforce, negative disables the check.
		expected int64
		err      error
	}
)

var (
	// ErrBodyLengthMismatch is returned by request body reads when the body does
	// not match the length set with ExpectBodyLength.
	ErrBodyLengthMismatch = errors.New("body length mismatch")
)

// countBody wraps request body to account bytes read from it.
func countBody(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := &bodyReader{ReadCloser: r.Body, expected: -1}
		r.Body = in

		h.ServeHTTP(w, r)

		metrics.AddInputBytes(in.countBytes.Load())
	})
}

// ExpectBodyLength makes further reads of r.Body fail with
// ErrBodyLengthMismatch once the body turns out to be shorter or longer than
// expected. Negative expected disables the check. It has no effect if r.Body
// was not wrapped by countBody.
func ExpectBodyLength(r *http.Request, expected int64) {
	if rc, ok := r.Body.(*bodyReader); ok {
		rc.expected = expected
	}
}

func (r *bodyReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	n, err := r.ReadCloser.Read(p)
	total := int64(r.countBytes.Add(uint64(n)))

	if r.expected < 0 {
		return n, err
	}

	if total > r.expected {
		n -= int(total - r.expected)
		r.err = ErrBodyLengthMismatch
		return n, r.err
	}

	if errors.Is(err, io.EOF) && total < r.expected {
		r.err = ErrBodyLengthMismatch
		return n, r.err
	}

	return n, err
}
