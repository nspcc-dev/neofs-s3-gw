package cache

import (
	"crypto/rand"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-s3-gw/api"
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

func TestObjectsListCache(t *testing.T) {
	var (
		cacheSize = 10
		objects   []*api.ObjectInfo
		userKey   = "key"
	)

	for i := 0; i < cacheSize; i++ {
		id := randID(t)
		objects = append(objects, &api.ObjectInfo{ID: id, Name: id.String()})
	}

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Name < objects[j].Name
	})

	t.Run("lifetime", func(t *testing.T) {
		var (
			cache    = NewObjectsListCache(testingCacheLifetime)
			cacheKey = ObjectsListKey{Key: userKey}
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
			cache    = NewObjectsListCache(testingCacheLifetime)
			cacheKey = ObjectsListKey{Key: userKey}
		)
		cache.Put(cacheKey, objects)
		actual := cache.Get(cacheKey)

		require.Equal(t, len(objects), len(actual))
		for i := range objects {
			require.Equal(t, objects[i], actual[i])
		}
	})

	t.Run("get cache with delimiter and prefix", func(t *testing.T) {
		cacheKey := ObjectsListKey{
			Key:       userKey,
			Delimiter: "/",
			Prefix:    "dir",
		}

		cache := NewObjectsListCache(testingCacheLifetime)
		cache.Put(cacheKey, objects)
		actual := cache.Get(cacheKey)

		require.Equal(t, len(objects), len(actual))
		for i := range objects {
			require.Equal(t, objects[i], actual[i])
		}
	})

	t.Run("get cache with other delimiter and prefix", func(t *testing.T) {
		var (
			cacheKey = ObjectsListKey{
				Key:       userKey,
				Delimiter: "/",
				Prefix:    "dir",
			}

			newKey = ObjectsListKey{
				Key:       "key",
				Delimiter: "*",
				Prefix:    "obj",
			}
		)

		cache := NewObjectsListCache(testingCacheLifetime)
		cache.Put(cacheKey, objects)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})

	t.Run("get cache with non-existing key", func(t *testing.T) {
		var (
			cacheKey = ObjectsListKey{
				Key: userKey,
			}
			newKey = ObjectsListKey{
				Key: "asdf",
			}
		)

		cache := NewObjectsListCache(testingCacheLifetime)
		cache.Put(cacheKey, objects)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})
}
