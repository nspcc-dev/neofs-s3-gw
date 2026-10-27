package layer

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type (
	dataErrReader struct {
		data []byte
		err  error
	}
)

const (
	content = "content"
)

var (
	errRead = errors.New("read error")
)

func TestDetectorReadError(t *testing.T) {
	var (
		d = newDetector(&dataErrReader{data: []byte(content), err: errRead})
	)

	_, err := d.Detect()
	require.ErrorIs(t, err, errRead)

	data, err := io.ReadAll(d.MultiReader())
	require.ErrorIs(t, err, errRead)
	require.Equal(t, content, string(data))
}

func (r *dataErrReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, r.err
}
