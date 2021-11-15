package cache

import (
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/object"
	objecttest "github.com/nspcc-dev/neofs-sdk-go/object/test"
	"github.com/stretchr/testify/require"
)

func getTestConfig() *Config {
	return &Config{
		Size:     10,
		Lifetime: 5 * time.Second,
	}
}

func TestCache(t *testing.T) {
	obj := objecttest.Object()
	address := object.NewAddress()
	address.SetContainerID(obj.ContainerID())
	address.SetObjectID(obj.ID())

	t.Run("check get", func(t *testing.T) {
		cache := New(getTestConfig())
		err := cache.Put(*obj)
		require.NoError(t, err)

		actual := cache.Get(address)
		require.Equal(t, obj, actual)
	})

	t.Run("check delete", func(t *testing.T) {
		cache := New(getTestConfig())
		err := cache.Put(*obj)
		require.NoError(t, err)

		cache.Delete(address)
		actual := cache.Get(address)
		require.Nil(t, actual)
	})
}
