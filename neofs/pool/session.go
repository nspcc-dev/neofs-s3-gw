package pool

import (
	"context"
	"crypto/ecdsa"
	"math"

	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-api-go/session"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type (
	queryParams struct {
		key  *ecdsa.PrivateKey
		addr refs.Address
		verb service.Token_Info_Verb
	}

	SessionParams struct {
		Addr refs.Address
		Conn *grpc.ClientConn
		Verb service.Token_Info_Verb
	}
)

func (p *pool) fetchToken(ctx context.Context, con *grpc.ClientConn) (*session.Token, error) {
	p.Lock()
	defer p.Unlock()

	// if we had token for current connection - return it
	if tkn, ok := p.tokens[con.Target()]; ok {
		return tkn, nil
	}

	// try to generate token for connection
	tkn, err := generateToken(ctx, con, p.key)
	if err != nil {
		return nil, err
	}

	p.tokens[con.Target()] = tkn
	return tkn, nil
}

// SessionToken returns session token for connection
func (p *pool) SessionToken(ctx context.Context, params *SessionParams) (*service.Token, error) {
	var (
		err error
		tkn *session.Token
	)

	if params.Conn == nil {
		return nil, errors.New("empty connection")
	} else if tkn, err = p.fetchToken(ctx, params.Conn); err != nil {
		return nil, err
	}

	return prepareToken(tkn, queryParams{
		key:  p.key,
		addr: params.Addr,
		verb: params.Verb,
	})
}

// creates token using
func generateToken(ctx context.Context, con *grpc.ClientConn, key *ecdsa.PrivateKey) (*service.Token, error) {
	owner, err := refs.NewOwnerID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	token := new(service.Token)
	token.SetOwnerID(owner)
	token.SetExpirationEpoch(math.MaxUint64)
	token.SetOwnerKey(crypto.MarshalPublicKey(&key.PublicKey))

	creator, err := session.NewGRPCCreator(con, key)
	if err != nil {
		return nil, err
	}

	res, err := creator.Create(ctx, token)
	if err != nil {
		return nil, err
	}

	token.SetID(res.GetID())
	token.SetSessionKey(res.GetSessionKey())

	return token, nil
}

func prepareToken(t *service.Token, p queryParams) (*service.Token, error) {
	sig := make([]byte, len(t.Signature))
	copy(sig, t.Signature)

	token := &service.Token{
		Token_Info: service.Token_Info{
			ID:            t.ID,
			OwnerID:       t.OwnerID,
			Verb:          t.Verb,
			Address:       t.Address,
			TokenLifetime: t.TokenLifetime,
			SessionKey:    t.SessionKey,
			OwnerKey:      t.OwnerKey,
		},
		Signature: sig,
	}

	token.SetAddress(p.addr)
	token.SetVerb(p.verb)

	err := service.AddSignatureWithKey(p.key, service.NewSignedSessionToken(token))
	if err != nil {
		return nil, err
	}

	return token, nil
}
