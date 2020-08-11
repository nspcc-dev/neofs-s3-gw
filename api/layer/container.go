package layer

import (
	"context"
	"time"

	"github.com/nspcc-dev/neofs-api-go/container"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
	"go.uber.org/zap"
)

type (
	BucketInfo struct {
		Name    string
		CID     refs.CID
		Created time.Time
	}

	ListObjectsParams struct {
		Bucket    string
		Prefix    string
		Token     string
		Delimiter string
		MaxKeys   int
	}
)

func (n *layer) containerInfo(ctx context.Context, cid refs.CID) (*BucketInfo, error) {
	rid := api.GetRequestID(ctx)
	bearer, err := auth.GetBearerToken(ctx)
	if err != nil {
		n.log.Error("could not receive bearer token",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	req := new(container.GetRequest)
	req.SetCID(cid)
	req.SetTTL(service.SingleForwardingTTL)
	// req.SetBearer(bearer)

	_ = bearer

	if err = service.SignRequestData(n.key, req); err != nil {
		n.log.Error("could not prepare request",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		n.log.Error("could not prepare client",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := container.NewServiceClient(conn).Get(ctx, req)
	if err != nil {
		n.log.Error("could not list buckets",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	_ = res

	return &BucketInfo{
		CID:     cid,
		Name:    cid.String(), // should be fetched from container.GetResponse
		Created: time.Time{},  // should be fetched from container.GetResponse
	}, nil
}

func (n *layer) containerList(ctx context.Context) ([]BucketInfo, error) {
	rid := api.GetRequestID(ctx)
	bearer, err := auth.GetBearerToken(ctx)
	if err != nil {
		n.log.Error("could not receive bearer token",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	req := new(container.ListRequest)
	req.OwnerID = n.uid
	req.SetTTL(service.SingleForwardingTTL)
	// req.SetBearer(bearer)

	_ = bearer

	if err := service.SignRequestData(n.key, req); err != nil {
		n.log.Error("could not prepare request",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	conn, err := n.cli.GetConnection(ctx)
	if err != nil {
		n.log.Error("could not prepare client",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	// todo: think about timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := container.NewServiceClient(conn).List(ctx, req)
	if err != nil {
		n.log.Error("could not list buckets",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]BucketInfo, 0, len(res.CID))
	for _, cid := range res.CID {
		info, err := n.containerInfo(ctx, cid)
		if err != nil {
			n.log.Error("could not fetch container info",
				zap.String("request_id", rid),
				zap.Error(err))
			continue
		}

		list = append(list, *info)
	}

	return list, nil
}
