package layer

import (
	"crypto/rand"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/stretchr/testify/require"
)

const testingCacheLifetime = 5 * time.Second

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
		objects []*ObjectInfo
		names   = []string{"b", "c", "d"}
	)
	for _, name := range names {
		objects = append(objects, &ObjectInfo{Name: name})
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
		actual := trimAfterObjectName(names[0], []*ObjectInfo{})
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
		objects     []*ObjectInfo
		ids         []*object.ID
		numberOfIDS = 3
	)

	for i := 0; i < numberOfIDS; i++ {
		id := randID(t)
		objects = append(objects, &ObjectInfo{id: id})
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

func TestObjectsListCache(t *testing.T) {
	var (
		cacheSize = 10
		objects   []*ObjectInfo
		userKey   = "key"
	)

	for i := 0; i < cacheSize; i++ {
		id := randID(t)
		objects = append(objects, &ObjectInfo{id: id, Name: id.String()})
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	t.Run("lifetime", func(t *testing.T) {
		var (
			cache    = newListObjectsCache(testingCacheLifetime)
			cacheKey = cacheOptions{key: userKey}
		)

		cache.Put(cacheKey, objects)

		condition := func() bool {
			return cache.Get(cacheKey) == nil
		}

		require.Never(t, condition, cache.cacheLifetime, time.Second)
		require.Eventually(t, condition, time.Second, 10*time.Millisecond)
	})

	t.Run("get cache with empty delimiter, empty prefix", func(t *testing.T) {
		var (
			cache    = newListObjectsCache(testingCacheLifetime)
			cacheKey = cacheOptions{key: userKey}
		)
		cache.Put(cacheKey, objects)
		actual := cache.Get(cacheKey)

		require.Equal(t, len(objects), len(actual))
		for i := range objects {
			require.Equal(t, objects[i], actual[i])
		}
	})

	t.Run("get cache with delimiter and prefix", func(t *testing.T) {
		cacheKey := cacheOptions{
			key:       userKey,
			delimiter: "/",
			prefix:    "dir",
		}

		cache := newListObjectsCache(testingCacheLifetime)
		cache.Put(cacheKey, objects)
		actual := cache.Get(cacheKey)

		require.Equal(t, len(objects), len(actual))
		for i := range objects {
			require.Equal(t, objects[i], actual[i])
		}
	})

	t.Run("get cache with other delimiter and prefix", func(t *testing.T) {
		var (
			cacheKey = cacheOptions{
				key:       userKey,
				delimiter: "/",
				prefix:    "dir",
			}

			newKey = cacheOptions{
				key:       "key",
				delimiter: "*",
				prefix:    "obj",
			}
		)

		cache := newListObjectsCache(testingCacheLifetime)
		cache.Put(cacheKey, objects)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})

	t.Run("get cache with non-existing key", func(t *testing.T) {
		var (
			cacheKey = cacheOptions{
				key: userKey,
			}
			newKey = cacheOptions{
				key: "asdf",
			}
		)

		cache := newListObjectsCache(testingCacheLifetime)
		cache.Put(cacheKey, objects)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})
}
