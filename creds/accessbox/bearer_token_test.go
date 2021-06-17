package accessbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/stretchr/testify/require"
)

func Test_tokens_encrypt_decrypt(t *testing.T) {
	var (
		tkn  = token.NewBearerToken()
		tkn2 = token.NewBearerToken()
	)
	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	rawTkn, err := tkn.Marshal()
	require.NoError(t, err)

	data, err := encrypt(cred, &cred.PublicKey, rawTkn)
	require.NoError(t, err)

	rawTkn2, err := decrypt(cred, &cred.PublicKey, data)
	require.NoError(t, err)

	err = tkn2.Unmarshal(rawTkn2)
	require.NoError(t, err)

	require.Equal(t, tkn, tkn2)
}

func Test_bearer_token_in_access_box(t *testing.T) {
	var (
		box  *AccessBox
		box2 AccessBox
		tkn  = token.NewBearerToken()
	)

	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	gate := NewGateData(tkn, &cred.PublicKey)
	box, _, err = PackTokens([]*GateData{gate}, nil)
	require.NoError(t, err)

	data, err := box.Marshal()
	require.NoError(t, err)

	err = box2.Unmarshal(data)
	require.NoError(t, err)

	tkns, err := box2.GetTokens(cred)
	require.NoError(t, err)

	require.Equal(t, tkn, tkns.BearerToken)
}

func Test_accessbox_multiple_keys(t *testing.T) {
	var (
		box *AccessBox
		tkn = token.NewBearerToken()
	)

	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	count := 10
	gates := make([]*GateData, 0, count)
	keys := make([]*ecdsa.PrivateKey, 0, count)
	{ // generate keys
		for i := 0; i < count; i++ {
			cred, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			gates = append(gates, NewGateData(tkn, &cred.PublicKey))
			keys = append(keys, cred)
		}
	}

	box, _, err = PackTokens(gates, nil)
	require.NoError(t, err)

	for i, k := range keys {
		tkns, err := box.GetTokens(k)
		require.NoError(t, err, "key #%d: %s failed", i, k)
		require.Equal(t, tkns.BearerToken, tkn)
	}
}

func Test_unknown_key(t *testing.T) {
	var (
		box *AccessBox
		tkn = token.NewBearerToken()
	)

	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wrongCred, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	gate := NewGateData(tkn, &cred.PublicKey)
	box, _, err = PackTokens([]*GateData{gate}, nil)
	require.NoError(t, err)

	_, err = box.GetTokens(wrongCred)
	require.Error(t, err)
}
