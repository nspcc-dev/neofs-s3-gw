package layer

import (
	"context"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/auth"
	"go.uber.org/zap"
)

type (
	BucketInfo struct {
		Name    string
		CID     *container.ID
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

func (n *layer) containerInfo(ctx context.Context, cid *container.ID) (*BucketInfo, error) {
	rid := api.GetRequestID(ctx)
	bearer, err := auth.GetBearerToken(ctx)
	if err != nil {
		n.log.Error("could not receive bearer token",
			zap.Stringer("cid", cid),
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	_ = bearer

	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		n.log.Error("could not prepare client",
			zap.Stringer("cid", cid),
			zap.String("request_id", rid),
			zap.Error(err))

		return nil, err
	}

	res, err := cli.GetContainer(ctx, cid, client.WithSession(tkn))
	if err != nil {
		n.log.Error("could not fetch container",
			zap.Stringer("cid", cid),
			zap.String("request_id", rid),
			zap.Error(err))

		return nil, err
	}

	_ = res

	return &BucketInfo{
		CID:     cid,
		Name:    cid.String(), // should be fetched from container.Attributes
		Created: time.Time{},  // should be fetched from container.Attributes
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

	_ = bearer

	cli, tkn, err := n.prepareClient(ctx)
	if err != nil {
		n.log.Error("could not prepare client",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	// own, err := GetOwnerID(bearer)
	// if err != nil {
	// 	n.log.Error("could not fetch owner id",
	// 		zap.String("request_id", rid),
	// 		zap.Error(err))
	// 	return nil, err
	// }

	res, err := cli.ListContainers(ctx, tkn.OwnerID(), client.WithSession(tkn))
	if err != nil {
		n.log.Error("could not fetch container",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]BucketInfo, 0, len(res))
	for _, cid := range res {
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
