package handler

import (
	"context"
	"crypto/ecdsa"
	"math"

	"github.com/minio/minio/neofs/api"
	"github.com/minio/minio/neofs/pool"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-api-go/session"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type (
	handler struct {
		log *zap.Logger
		cli pool.Client
		uid refs.OwnerID
		tkn *service.Token
		key *ecdsa.PrivateKey
	}

	Params struct {
		Cli pool.Client
		Log *zap.Logger
		Key *ecdsa.PrivateKey
	}

	queryParams struct {
		key  *ecdsa.PrivateKey
		addr refs.Address
		verb service.Token_Info_Verb
	}
)

var _ api.Handler = (*handler)(nil)

func New(ctx context.Context, p Params) (api.Handler, error) {
	var (
		err error
		uid refs.OwnerID
		tkn *service.Token
	)

	switch {
	case p.Key == nil:
		return nil, errors.New("empty private key")
	case p.Cli == nil:
		return nil, errors.New("empty gRPC client")
	case p.Log == nil:
		return nil, errors.New("empty logger")
	}

	if uid, err = refs.NewOwnerID(&p.Key.PublicKey); err != nil {
		return nil, errors.Wrap(err, "could not fetch OwnerID")
	} else if tkn, err = generateToken(ctx, p.Cli, p.Key); err != nil {
		return nil, errors.Wrap(err, "could not prepare session token")
	}

	return &handler{
		uid: uid,
		tkn: tkn,
		key: p.Key,
		log: p.Log,
		cli: p.Cli,
	}, nil
}

func generateToken(ctx context.Context, cli pool.Client, key *ecdsa.PrivateKey) (*service.Token, error) {
	owner, err := refs.NewOwnerID(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	token := new(service.Token)
	token.SetOwnerID(owner)
	token.SetExpirationEpoch(math.MaxUint64)
	token.SetOwnerKey(crypto.MarshalPublicKey(&key.PublicKey))

	conn, err := cli.GetConnection(ctx)
	if err != nil {
		return nil, err
	}

	creator, err := session.NewGRPCCreator(conn, key)
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
