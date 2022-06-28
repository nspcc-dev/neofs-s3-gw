package cache

import (
	"testing"
	"time"

	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const testingCacheLifetime = 5 * time.Second
const testingCacheSize = 10

func getTestObjectsListConfig() *Config {
	return &Config{
		Size:     testingCacheSize,
		Lifetime: testingCacheLifetime,
		Logger:   zap.NewExample(),
	}
}

func TestObjectsListCache(t *testing.T) {
	var (
		listSize        = 10
		ids             []oid.ID
		cidKey, cidKey2 = cidtest.ID(), cidtest.ID()
	)

	for i := 0; i < listSize; i++ {
		ids = append(ids, oidtest.ID())
	}

	t.Run("lifetime", func(t *testing.T) {
		var (
			config   = getTestObjectsListConfig()
			cache    = NewObjectsListCache(config)
			cacheKey = ObjectsListKey{cid: cidKey}
		)

		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		condition := func() bool {
			return cache.Get(cacheKey) == nil
		}

		require.Never(t, condition, config.Lifetime, time.Second)
		require.Eventually(t, condition, time.Second, 10*time.Millisecond)
	})

	t.Run("get cache with empty prefix", func(t *testing.T) {
		var (
			cache    = NewObjectsListCache(getTestObjectsListConfig())
			cacheKey = ObjectsListKey{cid: cidKey}
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
			cid:    cidKey,
			prefix: "dir",
		}

		cache := NewObjectsListCache(getTestObjectsListConfig())
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
				cid:    cidKey,
				prefix: "dir",
			}

			newKey = ObjectsListKey{
				cid:    cidKey,
				prefix: "obj",
			}
		)

		cache := NewObjectsListCache(getTestObjectsListConfig())
		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})

	t.Run("get cache with non-existing key", func(t *testing.T) {
		var (
			cacheKey = ObjectsListKey{
				cid: cidKey,
			}
			newKey = ObjectsListKey{
				cid: cidKey2,
			}
		)

		cache := NewObjectsListCache(getTestObjectsListConfig())
		err := cache.Put(cacheKey, ids)
		require.NoError(t, err)

		actual := cache.Get(newKey)
		require.Nil(t, actual)
	})
}

func TestCleanCacheEntriesChangedWithPutObject(t *testing.T) {
	var (
		id   = cidtest.ID()
		oids = []oid.ID{oidtest.ID()}
		keys []ObjectsListKey
	)

	for _, p := range []string{"", "dir/", "dir/lol/"} {
		keys = append(keys, ObjectsListKey{cid: id, prefix: p})
	}

	t.Run("put object to the root of the bucket", func(t *testing.T) {
		config := getTestObjectsListConfig()
		config.Lifetime = time.Minute
		cache := NewObjectsListCache(config)
		for _, k := range keys {
			err := cache.Put(k, oids)
			require.NoError(t, err)
		}
		cache.CleanCacheEntriesContainingObject("obj1", id)
		for _, k := range keys {
			list := cache.Get(k)
			if k.prefix == "" {
				require.Nil(t, list)
			} else {
				require.NotNil(t, list)
			}
		}
	})

	t.Run("put object to dir/", func(t *testing.T) {
		config := getTestObjectsListConfig()
		config.Lifetime = time.Minute
		cache := NewObjectsListCache(config)
		for _, k := range keys {
			err := cache.Put(k, oids)
			require.NoError(t, err)
		}
		cache.CleanCacheEntriesContainingObject("dir/obj", id)
		for _, k := range keys {
			list := cache.Get(k)
			if k.prefix == "" || k.prefix == "dir/" {
				require.Nil(t, list)
			} else {
				require.NotNil(t, list)
			}
		}
	})

	t.Run("put object to dir/lol/", func(t *testing.T) {
		config := getTestObjectsListConfig()
		config.Lifetime = time.Minute
		cache := NewObjectsListCache(config)
		for _, k := range keys {
			err := cache.Put(k, oids)
			require.NoError(t, err)
		}
		cache.CleanCacheEntriesContainingObject("dir/lol/obj", id)
		for _, k := range keys {
			list := cache.Get(k)
			require.Nil(t, list)
		}
	})
}
