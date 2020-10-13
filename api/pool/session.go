package pool

import (
	"context"
	"crypto/ecdsa"
	"math"

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
	tkn, err := prepareToken(ctx, conn, p.key)
	if err != nil {
		return nil, err
	}

	// save token for current connection
	p.tokens[conn.Target()] = tkn

	return tkn, nil
}

// creates token using
func prepareToken(ctx context.Context, con *grpc.ClientConn, key *ecdsa.PrivateKey) (*token.SessionToken, error) {
	cli, err := client.New(key, client.WithGRPCConnection(con))
	if err != nil {
		return nil, err
	}

	return cli.CreateSession(ctx, math.MaxUint64)
}
