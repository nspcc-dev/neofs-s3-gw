package cache

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/stretchr/testify/require"
)

const testingCacheLifetime = 5 * time.Second
const testingCacheSize = 10

func getTestObjectsListConfig() *Config {
	return &Config{
		Size:     testingCacheSize,
		Lifetime: testingCacheLifetime,
	}
}

func randID(t *testing.T) *oid.ID {
	var id oid.ID
	id.SetSHA256(randSHA256Checksum(t))

	return &id
}

func randSHA256Checksum(t *testing.T) (cs [sha256.Size]byte) {
	_, err := rand.Read(cs[:])
	require.NoError(t, err)

	return
}

func TestObjectsListCache(t *testing.T) {
	var (
		listSize = 10
		ids      []oid.ID
		userKey  = "key"
	)

	for i := 0; i < listSize; i++ {
		ids = append(ids, *randID(t))
	}

	t.Run("lifetime", func(t *testing.T) {
		var (
			config   = getTestObjectsListConfig()
			cache    = NewObjectsListCache(config)
			cacheKey = ObjectsListKey{cid: userKey}
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
				cid:    userKey,
				prefix: "dir",
			}

			newKey = ObjectsListKey{
				cid:    "key",
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
				cid: userKey,
			}
			newKey = ObjectsListKey{
				cid: "asdf",
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
		id   cid.ID
		oids = []oid.ID{*randID(t)}
		keys []ObjectsListKey
	)

	for _, p := range []string{"", "dir/", "dir/lol/"} {
		keys = append(keys, ObjectsListKey{cid: id.String(), prefix: p})
	}

	t.Run("put object to the root of the bucket", func(t *testing.T) {
		config := getTestObjectsListConfig()
		config.Lifetime = time.Minute
		cache := NewObjectsListCache(config)
		for _, k := range keys {
			err := cache.Put(k, oids)
			require.NoError(t, err)
		}
		cache.CleanCacheEntriesContainingObject("obj1", &id)
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
		cache.CleanCacheEntriesContainingObject("dir/obj", &id)
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
		cache.CleanCacheEntriesContainingObject("dir/lol/obj", &id)
		for _, k := range keys {
			list := cache.Get(k)
			require.Nil(t, list)
		}
	})
}
