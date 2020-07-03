package layer

import (
	"context"
	"time"

	"github.com/nspcc-dev/neofs-api-go/container"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
)

func (n *neofsObject) containerList(ctx context.Context) ([]refs.CID, error) {
	req := new(container.ListRequest)
	req.OwnerID = n.owner
	req.SetTTL(service.SingleForwardingTTL)
	req.SetVersion(APIVersion)

	err := service.SignRequestData(n.key, req)
	if err != nil {
		return nil, err
	}

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := container.NewServiceClient(conn).List(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.CID, nil
}
