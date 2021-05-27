package layer

import (
	"context"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"go.uber.org/zap"
)

type (
	// BucketInfo stores basic bucket data.
	BucketInfo struct {
		Name    string
		CID     *container.ID
		Owner   *owner.ID
		Created time.Time
	}

	// ListObjectsParams represents object listing request parameters.
	ListObjectsParams struct {
		Bucket    string
		Prefix    string
		Token     string
		Delimiter string
		MaxKeys   int
	}
)

func (n *layer) containerInfo(ctx context.Context, cid *container.ID) (*BucketInfo, error) {
	var (
		err error
		res *container.Container
		rid = api.GetRequestID(ctx)

		info = &BucketInfo{
			CID:  cid,
			Name: cid.String(),
		}
	)

	conn, _, err := n.cli.ConnectionArtifacts()
	if err != nil {
		n.log.Error("failed to get connection from the pool",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}
	res, err = conn.GetContainer(ctx, cid)
	if err != nil {
		n.log.Error("could not fetch container",
			zap.Stringer("cid", cid),
			zap.String("request_id", rid),
			zap.Error(err))

		return nil, err
	}

	info.Owner = res.OwnerID()

	for _, attr := range res.Attributes() {
		switch key, val := attr.Key(), attr.Value(); key {
		case container.AttributeName:
			info.Name = val
		case container.AttributeTimestamp:
			unix, err := strconv.ParseInt(attr.Value(), 10, 64)
			if err != nil {
				n.log.Error("could not parse container creation time",
					zap.Stringer("cid", cid),
					zap.String("request_id", rid),
					zap.String("created_at", val),
					zap.Error(err))

				continue
			}

			info.Created = time.Unix(unix, 0)
		}
	}

	return info, nil
}

func (n *layer) containerList(ctx context.Context) ([]*BucketInfo, error) {
	var (
		err error
		own = n.Owner(ctx)
		res []*container.ID
		rid = api.GetRequestID(ctx)
	)

	conn, _, err := n.cli.ConnectionArtifacts()
	if err != nil {
		n.log.Error("failed to get connection from the pool",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}
	res, err = conn.ListContainers(ctx, own)
	if err != nil {
		n.log.Error("could not fetch container",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]*BucketInfo, 0, len(res))
	for _, cid := range res {
		info, err := n.containerInfo(ctx, cid)
		if err != nil {
			n.log.Error("could not fetch container info",
				zap.String("request_id", rid),
				zap.Error(err))
			continue
		}

		list = append(list, info)
	}

	return list, nil
}
