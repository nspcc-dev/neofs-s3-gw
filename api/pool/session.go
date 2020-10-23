package pool

import (
	"context"
	"math"

	"go.uber.org/zap"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"google.golang.org/grpc"
)

// SessionToken returns session token for connection
func (p *pool) Token(ctx context.Context, conn *grpc.ClientConn) (*token.SessionToken, error) {
	p.Lock()
	defer p.Unlock()

	if tkn, ok := p.tokens[conn.Target()]; ok && tkn != nil {
		return tkn, nil
	}

	// prepare session token
	tkn, err := p.prepareToken(ctx, conn)
	if err != nil {
		return nil, err
	}

	// save token for current connection
	p.tokens[conn.Target()] = tkn

	return tkn, nil
}

// creates token using
func (p *pool) prepareToken(ctx context.Context, conn *grpc.ClientConn) (*token.SessionToken, error) {
	cli, err := client.New(p.key, client.WithGRPCConnection(conn))
	if err != nil {
		return nil, err
	}

	tkn, err := cli.CreateSession(ctx, math.MaxUint64)
	if err != nil {
		return nil, err
	}

	p.log.Info("token created for connection",
		zap.String("address", conn.Target()),
		zap.Stringer("owner", tkn.OwnerID()))

	return tkn, err
}
