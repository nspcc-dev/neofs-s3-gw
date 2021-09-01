package cache

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/stretchr/testify/require"
)

const testingCacheLifetime = 5 * time.Second
const testingCacheSize = 10

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
		ids       []*object.ID
		userKey   = "key"
	)

	for i := 0; i < cacheSize; i++ {
		id := randID(t)
		ids = append(ids, id)
	}

	t.Run("lifetime", func(t *testing.T) {
		var (
			cache    = NewObjectsListCache(testingCacheSize, testingCacheLifetime)
			cacheKey = ObjectsListKey{cid: userKey}
		)

		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		condition := func() bool {
			return cache.Get(cacheKey) == nil
		}

		require.Never(t, condition, cache.lifetime, time.Second)
		require.Eventually(t, condition, time.Second, 10*time.Millisecond)
	})

	t.Run("get cache with empty prefix", func(t *testing.T) {
		var (
			cache    = NewObjectsListCache(testingCacheSize, testingCacheLifetime)
			cacheKey = ObjectsListKey{cid: userKey}
		)
		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		actual := cache.Get(cacheKey)

		require.Equal(t, len(ids), len(actual))
		for i := range ids {
			require.Equal(t, ids[i], actual[i])
		}
	})

	t.Run("get cache with prefix", func(t *testing.T) {
		cacheKey := ObjectsListKey{
			cid:    userKey,
			prefix: "dir",
		}

		cache := NewObjectsListCache(testingCacheSize, testingCacheLifetime)
		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		actual := cache.Get(cacheKey)

		require.Equal(t, len(ids), len(actual))
		for i := range ids {
			require.Equal(t, ids[i], actual[i])
		}
	})

	t.Run("get cache with other prefix", func(t *testing.T) {
		var (
			cacheKey = ObjectsListKey{
				cid:    userKey,
				prefix: "dir",
			}

			newKey = ObjectsListKey{
				cid:    "key",
				prefix: "obj",
			}
		)

		cache := NewObjectsListCache(testingCacheSize, testingCacheLifetime)
		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})

	t.Run("get cache with non-existing key", func(t *testing.T) {
		var (
			cacheKey = ObjectsListKey{
				cid: userKey,
			}
			newKey = ObjectsListKey{
				cid: "asdf",
			}
		)

		cache := NewObjectsListCache(testingCacheSize, testingCacheLifetime)
		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})
}
