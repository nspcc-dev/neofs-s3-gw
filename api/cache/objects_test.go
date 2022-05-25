package cache

import (
	"testing"
	"time"

	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
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
	objID, _ := obj.ID()
	cnrID, _ := obj.ContainerID()

	var addr oid.Address
	addr.SetContainer(cnrID)
	addr.SetObject(objID)

	t.Run("check get", func(t *testing.T) {
		cache := New(getTestConfig())
		err := cache.Put(*obj)
		require.NoError(t, err)

		actual := cache.Get(addr)
		require.Equal(t, obj, actual)
	})

	t.Run("check delete", func(t *testing.T) {
		cache := New(getTestConfig())
		err := cache.Put(*obj)
		require.NoError(t, err)

		cache.Delete(addr)
		actual := cache.Get(addr)
		require.Nil(t, actual)
	})
}
