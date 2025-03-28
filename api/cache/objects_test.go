package cache

import (
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	objecttest "github.com/nspcc-dev/neofs-sdk-go/object/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func getTestConfig() *Config {
	return &Config{
		Size:     10,
		Lifetime: 5 * time.Second,
		Logger:   zap.NewExample(),
	}
}

func TestCache(t *testing.T) {
	obj := objecttest.Object()

	addr := oid.NewAddress(obj.GetContainerID(), obj.GetID())

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo: &data.ObjectInfo{
			ID:  addr.Object(),
			CID: addr.Container(),
		},
		NodeVersion: &data.NodeVersion{
			FilePath:      "obj",
			IsUnversioned: true,
		},
		IsLatest: true,
	}

	t.Run("check get", func(t *testing.T) {
		cache := New(getTestConfig())
		err := cache.PutObject(extObjInfo)
		require.NoError(t, err)

		actual := cache.GetObject(addr)
		require.Equal(t, extObjInfo, actual)
	})

	t.Run("check delete", func(t *testing.T) {
		cache := New(getTestConfig())
		err := cache.PutObject(extObjInfo)
		require.NoError(t, err)

		cache.Delete(addr)
		actual := cache.GetObject(addr)
		require.Nil(t, actual)
	})
}
