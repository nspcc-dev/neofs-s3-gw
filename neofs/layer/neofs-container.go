package layer

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/minio/minio/auth"
	"github.com/nspcc-dev/neofs-api-go/container"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
)

func (n *neofsObject) containerList(ctx context.Context) ([]refs.CID, error) {
	req := new(container.ListRequest)
	req.OwnerID = n.owner
	req.SetTTL(service.SingleForwardingTTL)
	req.SetVersion(APIVersion)
	req.SetBearer(auth.GetBearerToken(ctx))

	err := service.SignRequestData(n.key, req)
	if err != nil {
		n.log.Error("could not prepare request",
			zap.Error(err))
		return nil, err
	}

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		n.log.Error("could not prepare client",
			zap.Error(err))
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := container.NewServiceClient(conn).List(ctx, req)
	if err != nil {
		n.log.Error("could not list buckets",
			zap.Error(err))
		return nil, err
	}

	return res.CID, nil
}
