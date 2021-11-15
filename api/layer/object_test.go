package layer

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/stretchr/testify/require"
)

func randID(t *testing.T) *object.ID {
	id := object.NewID()
	id.SetSHA256(randSHA256Checksum(t))

	return id
}

func randSHA256Checksum(t *testing.T) (cs [sha256.Size]byte) {
	_, err := rand.Read(cs[:])
	require.NoError(t, err)

	return
}

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
		ids         []*object.ID
		numberOfIDS = 3
	)

	for i := 0; i < numberOfIDS; i++ {
		id := randID(t)
		objects = append(objects, &data.ObjectInfo{ID: id})
		ids = append(ids, id)
	}

	t.Run("existing id", func(t *testing.T) {
		actual := trimAfterObjectID(ids[0].String(), objects)
		require.Equal(t, objects[1:], actual)
	})

	t.Run("second to last id", func(t *testing.T) {
		actual := trimAfterObjectID(ids[len(ids)-2].String(), objects)
		require.Equal(t, objects[len(objects)-1:], actual)
	})

	t.Run("non-existing id", func(t *testing.T) {
		actual := trimAfterObjectID("z", objects)
		require.Nil(t, actual)
	})

	t.Run("last id", func(t *testing.T) {
		actual := trimAfterObjectID(ids[len(ids)-1].String(), objects)
		require.Empty(t, actual)
	})

	t.Run("empty id", func(t *testing.T) {
		actual := trimAfterObjectID("", objects)
		require.Nil(t, actual)
	})
}
