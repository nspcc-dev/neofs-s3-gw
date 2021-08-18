package cache

import (
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"

	objecttest "github.com/nspcc-dev/neofs-api-go/pkg/object/test"
	"github.com/stretchr/testify/require"
)

const (
	cachesize = 10
	lifetime  = time.Second * 5
)

func TestCache(t *testing.T) {
	obj := objecttest.Object()
	address := object.NewAddress()
	address.SetContainerID(obj.ContainerID())
	address.SetObjectID(obj.ID())

	t.Run("check get", func(t *testing.T) {
		cache := New(cachesize, lifetime)
		err := cache.Put(*obj)
		require.NoError(t, err)

		actual := cache.Get(address)
		require.Equal(t, obj, actual)
	})

	t.Run("check delete", func(t *testing.T) {
		cache := New(cachesize, lifetime)
		err := cache.Put(*obj)
		require.NoError(t, err)

		cache.Delete(address)
		actual := cache.Get(address)
		require.Nil(t, actual)
	})
}
