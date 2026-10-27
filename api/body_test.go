package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpectBodyLength(t *testing.T) {
	const content = "content"

	serve := func(f func(r *http.Request)) {
		h := countBody(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { f(r) }))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/", strings.NewReader(content)))
	}

	readBody := func(expected int64) ([]byte, error) {
		var (
			data []byte
			err  error
		)

		serve(func(r *http.Request) {
			ExpectBodyLength(r, expected)
			data, err = io.ReadAll(r.Body)
		})

		return data, err
	}

	t.Run("exact", func(t *testing.T) {
		data, err := readBody(int64(len(content)))
		require.NoError(t, err)
		require.Equal(t, content, string(data))
	})

	t.Run("unknown", func(t *testing.T) {
		data, err := readBody(-1)
		require.NoError(t, err)
		require.Equal(t, content, string(data))
	})

	t.Run("shortened", func(t *testing.T) {
		data, err := readBody(int64(len(content)) + 1)
		require.ErrorIs(t, err, ErrBodyLengthMismatch)
		require.Equal(t, content, string(data))
	})

	t.Run("extended", func(t *testing.T) {
		data, err := readBody(int64(len(content)) - 1)
		require.ErrorIs(t, err, ErrBodyLengthMismatch)
		require.Equal(t, content[:len(content)-1], string(data))
	})

	t.Run("sticky error", func(t *testing.T) {
		serve(func(r *http.Request) {
			ExpectBodyLength(r, int64(len(content))-1)

			_, err := io.ReadAll(r.Body)
			require.ErrorIs(t, err, ErrBodyLengthMismatch)

			n, err := r.Body.Read(make([]byte, len(content)))
			require.Zero(t, n)
			require.ErrorIs(t, err, ErrBodyLengthMismatch)
		})
	})

	t.Run("not wrapped", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(content))
		ExpectBodyLength(r, 1)

		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Equal(t, content, string(data))
	})
}
