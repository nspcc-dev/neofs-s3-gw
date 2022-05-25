package layer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io/ioutil"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
)

func TestTrimAfterObjectName(t *testing.T) {
	var (
		objects []*data.ObjectInfo
		names   = []string{"b", "c", "d"}
	)
	for _, name := range names {
		objects = append(objects, &data.ObjectInfo{Name: name})
	}

	t.Run("startafter before all objects", func(t *testing.T) {
		actual := trimAfterObjectName("a", objects)
		require.Equal(t, objects, actual)
	})

	t.Run("startafter first object", func(t *testing.T) {
		actual := trimAfterObjectName(names[0], objects)
		require.Equal(t, objects[1:], actual)
	})

	t.Run("startafter second-to-last object", func(t *testing.T) {
		actual := trimAfterObjectName(names[len(names)-2], objects)
		require.Equal(t, objects[len(objects)-1:], actual)
	})

	t.Run("startafter last object", func(t *testing.T) {
		actual := trimAfterObjectName(names[len(names)-1], objects)
		require.Empty(t, actual)
	})

	t.Run("startafter after all objects", func(t *testing.T) {
		actual := trimAfterObjectName("z", objects)
		require.Nil(t, actual)
	})

	t.Run("empty objects", func(t *testing.T) {
		actual := trimAfterObjectName(names[0], []*data.ObjectInfo{})
		require.Nil(t, actual)
	})

	t.Run("nil objects", func(t *testing.T) {
		actual := trimAfterObjectName(names[0], nil)
		require.Nil(t, actual)
	})

	t.Run("empty startafter", func(t *testing.T) {
		actual := trimAfterObjectName("", objects)
		require.Equal(t, objects, actual)
	})
}

func TestTrimAfterObjectID(t *testing.T) {
	var (
		objects     []*data.ObjectInfo
		ids         []oid.ID
		numberOfIDS = 3
	)

	for i := 0; i < numberOfIDS; i++ {
		id := oidtest.ID()
		objects = append(objects, &data.ObjectInfo{ID: id})
		ids = append(ids, id)
	}

	t.Run("existing id", func(t *testing.T) {
		actual := trimAfterObjectID(ids[0].EncodeToString(), objects)
		require.Equal(t, objects[1:], actual)
	})

	t.Run("second to last id", func(t *testing.T) {
		actual := trimAfterObjectID(ids[len(ids)-2].EncodeToString(), objects)
		require.Equal(t, objects[len(objects)-1:], actual)
	})

	t.Run("non-existing id", func(t *testing.T) {
		actual := trimAfterObjectID("z", objects)
		require.Nil(t, actual)
	})

	t.Run("last id", func(t *testing.T) {
		actual := trimAfterObjectID(ids[len(ids)-1].EncodeToString(), objects)
		require.Empty(t, actual)
	})

	t.Run("empty id", func(t *testing.T) {
		actual := trimAfterObjectID("", objects)
		require.Nil(t, actual)
	})
}

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

	dst, err := ioutil.ReadAll(wrappedReader)
	require.NoError(t, err)
	require.Equal(t, src, dst)
	require.Equal(t, h[:], streamHash.Sum(nil))
}
