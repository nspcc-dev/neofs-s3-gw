package pool

import (
	"context"
	"crypto/ecdsa"

	"github.com/nspcc-dev/neofs-api-go/v2/client"
	"github.com/nspcc-dev/neofs-api-go/v2/netmap"
	"github.com/nspcc-dev/neofs-api-go/v2/signature"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type v2Ping struct {
	req *netmap.LocalNodeInfoRequest
}

func newV2Ping(key *ecdsa.PrivateKey) (Pinger, error) {
	req := new(netmap.LocalNodeInfoRequest)

	if err := signature.SignServiceMessage(key, req); err != nil {
		return nil, errors.Wrap(err, "could not sign `PingRequest`")
	}

	return &v2Ping{req: req}, nil
}

func (v *v2Ping) Call(ctx context.Context, conn *grpc.ClientConn) error {
	if cli, err := netmap.NewClient(netmap.WithGlobalOpts(client.WithGRPCConn(conn))); err != nil {
		return err
	} else if _, err := cli.LocalNodeInfo(ctx, v.req); err != nil {
		return err
	}

	return nil
}
