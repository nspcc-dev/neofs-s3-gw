package layer

import (
	"crypto/ecdsa"
	"math"
	"testing"

	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-api-go/session"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/nspcc-dev/neofs-crypto/test"
	"github.com/stretchr/testify/require"
)

type args struct {
	t *service.Token
	p queryParams
}

func newTestToken(t *testing.T, key *ecdsa.PrivateKey, until uint64) *service.Token {
	owner, err := refs.NewOwnerID(&key.PublicKey)
	require.NoError(t, err)

	token := new(service.Token)
	token.SetOwnerID(owner)
	token.SetExpirationEpoch(until)
	token.SetOwnerKey(crypto.MarshalPublicKey(&key.PublicKey))

	// generate token ID
	tokenID, err := refs.NewUUID()
	require.NoError(t, err)

	pToken, err := session.NewPrivateToken(until)
	require.NoError(t, err)

	pkBytes, err := session.PublicSessionToken(pToken)
	require.NoError(t, err)

	token.SetID(tokenID)
	token.SetSessionKey(pkBytes)

	return token
}

func newTestArgs(t *testing.T, key *ecdsa.PrivateKey) args {
	token := newTestToken(t, key, math.MaxUint64)

	addr := refs.Address{}

	return args{
		t: token,
		p: queryParams{key: key, addr: addr, verb: service.Token_Info_Put},
	}
}

func Test_prepareToken(t *testing.T) {

	key1 := test.DecodeKey(1)
	key2 := test.DecodeKey(2)

	tests := []struct {
		name    string
		args    args
		want    *service.Token
		wantErr bool
	}{
		{
			name:    "should not fail, key1",
			args:    newTestArgs(t, key1),
			want:    newTestToken(t, key1, math.MaxUint64),
			wantErr: false,
		},
		{
			name:    "should not fail, key 2",
			args:    newTestArgs(t, key2),
			want:    newTestToken(t, key2, math.MaxUint64),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := prepareToken(tt.args.t, tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("prepareToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}
