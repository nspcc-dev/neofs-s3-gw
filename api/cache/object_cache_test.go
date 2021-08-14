package cache

import (
	"testing"
	"time"

	objecttest "github.com/nspcc-dev/neofs-api-go/pkg/object/test"
	"github.com/stretchr/testify/require"
)

const (
	cachesize = 10
	lifetime  = time.Second * 5
)

func TestCache(t *testing.T) {
	var (
		address = objecttest.Address()
		object  = objecttest.Object()
	)

	t.Run("check get", func(t *testing.T) {
		cache := New(cachesize, lifetime)
		err := cache.Put(address, *object)
		require.NoError(t, err)

		actual := cache.Get(address)
		require.Equal(t, object, actual)
	})

	t.Run("check delete", func(t *testing.T) {
		cache := New(cachesize, lifetime)
		err := cache.Put(address, *object)
		require.NoError(t, err)

		cache.Delete(address)
		actual := cache.Get(address)
		require.Nil(t, actual)
	})
}
