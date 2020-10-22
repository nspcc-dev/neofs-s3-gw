package layer

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func testBuffer(t *testing.T) []byte {
	buf := make([]byte, 1024)
	_, err := rand.Read(buf)
	require.NoError(t, err)

	return buf
}

func TestOffsetWriter(t *testing.T) {
	b := testBuffer(t)
	k := 64
	d := len(b) / k
	s := int64(len(b))

	t.Run("1024 / 100 / 100 bytes success", func(t *testing.T) {
		w := new(bytes.Buffer)
		o := int64(100)
		l := int64(100)

		wt := newWriter(w, o, l)
		for i := 0; i < k; i++ {
			_, err := wt.Write(b[i*d : (i+1)*d])
			require.NoError(t, err)
		}

		wo := wt.(*offsetWriter)

		require.Equal(t, o, wo.skipped)
		require.Equal(t, l, wo.written)
		require.Equal(t, b[o:o+l], w.Bytes())
	})

	t.Run("1024 / 0 / 100 bytes success", func(t *testing.T) {
		w := new(bytes.Buffer)
		o := int64(0)
		l := int64(100)

		wt := newWriter(w, o, l)
		for i := 0; i < k; i++ {
			_, err := wt.Write(b[i*d : (i+1)*d])
			require.NoError(t, err)
		}

		wo := wt.(*offsetWriter)

		require.Equal(t, o, wo.skipped)
		require.Equal(t, l, wo.written)
		require.Equal(t, b[o:o+l], w.Bytes())
	})

	t.Run("1024 / 0 / 1024 bytes success", func(t *testing.T) {
		w := new(bytes.Buffer)
		o := int64(0)
		l := int64(1024)

		wt := newWriter(w, o, l)
		for i := 0; i < k; i++ {
			_, err := wt.Write(b[i*d : (i+1)*d])
			require.NoError(t, err)
		}

		wo := wt.(*offsetWriter)

		require.Equal(t, o, wo.skipped)
		require.Equal(t, l, wo.written)
		require.Equal(t, b[o:o+l], w.Bytes())
	})

	t.Run("should read all data when empty length passed", func(t *testing.T) {
		w := new(bytes.Buffer)
		o := int64(0)
		l := int64(0)

		wt := newWriter(w, o, l)
		for i := 0; i < k; i++ {
			_, err := wt.Write(b[i*d : (i+1)*d])
			require.NoError(t, err)
		}

		wo := wt.(*offsetWriter)

		require.Equal(t, o, wo.skipped)
		require.Equal(t, s, wo.written)
		require.Equal(t, b, w.Bytes())
	})

	t.Run("should read all data when empty length passed", func(t *testing.T) {
		w := new(bytes.Buffer)
		o := int64(0)
		l := s + 1

		wt := newWriter(w, o, l)
		for i := 0; i < k; i++ {
			_, err := wt.Write(b[i*d : (i+1)*d])
			require.NoError(t, err)
		}

		wo := wt.(*offsetWriter)

		require.Equal(t, o, wo.skipped)
		require.Equal(t, s, wo.written)
		require.Equal(t, b, w.Bytes())
	})
}
