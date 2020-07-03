package layer

import (
	"context"
	"time"

	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-api-go/state"
)

func (n *neofsObject) statusHealth(ctx context.Context) bool {
	req := new(state.HealthRequest)
	req.SetTTL(service.NonForwardingTTL)
	req.SetVersion(APIVersion)

	err := service.SignDataWithSessionToken(n.key, req)
	if err != nil {
		return false
	}

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return false
	}

	// 1 second timeout is the same as in gateway-common.go
	// see: cmd/gateway-common.go:295
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	res, err := state.NewStatusClient(conn).HealthCheck(ctx, req)

	return err != nil && res != nil && res.Healthy
}
