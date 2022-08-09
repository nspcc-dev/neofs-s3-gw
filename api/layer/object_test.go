package layer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrapReader(t *testing.T) {
	src := make([]byte, 1024*1024+1)
	_, err := rand.Read(src)
	require.NoError(t, err)
	h := sha256.Sum256(src)

	streamHash := sha256.New()
	reader := bytes.NewReader(src)
	wrappedReader := wrapReader(reader, 64*1024, func(buf []byte) {
		streamHash.Write(buf)
	})

	dst, err := io.ReadAll(wrappedReader)
	require.NoError(t, err)
	require.Equal(t, src, dst)
	require.Equal(t, h[:], streamHash.Sum(nil))
}
