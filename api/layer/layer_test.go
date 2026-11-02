package layer

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestIsErrObjectGone(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		gone bool
	}{
		{name: "already removed", err: apistatus.ObjectAlreadyRemoved{}, gone: true},
		{name: "already removed pointer", err: new(apistatus.ObjectAlreadyRemoved), gone: true},
		{name: "already removed wrapped", err: fmt.Errorf("read header: %w", apistatus.ErrObjectAlreadyRemoved), gone: true},
		{name: "not found", err: apistatus.ErrObjectNotFound, gone: true},
		{name: "not found wrapped", err: fmt.Errorf("read header: %w", apistatus.ErrObjectNotFound), gone: true},
		{name: "access denied", err: apistatus.ErrObjectAccessDenied, gone: false},
		{name: "other", err: errors.New("connection refused"), gone: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.gone, IsErrObjectGone(tc.err))
		})
	}
}

func TestNamesCacheEnabled(t *testing.T) {
	var (
		owner = usertest.ID()
		cnrID = cidtest.ID()
		info  = &data.ComprehensiveObjectInfo{ID: oidtest.ID()}
	)

	t.Run("disabled by default", func(t *testing.T) {
		c := NewCache(DefaultCachesConfigs(zap.NewNop()))

		c.PutObjectByName(owner, cnrID, "obj", info)
		require.Nil(t, c.GetObjectByName(owner, cnrID, "obj"))
		c.DeleteObjectName(cnrID, "obj")
	})

	t.Run("enabled", func(t *testing.T) {
		cfg := DefaultCachesConfigs(zap.NewNop())
		cfg.Names.Lifetime = time.Minute
		c := NewCache(cfg)

		c.PutObjectByName(owner, cnrID, "obj", info)
		require.Equal(t, info, c.GetObjectByName(owner, cnrID, "obj"))

		c.DeleteObjectName(cnrID, "obj")
		require.Nil(t, c.GetObjectByName(owner, cnrID, "obj"))
	})
}
