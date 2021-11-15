package accessbox

import (
	"testing"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/token"
	"github.com/stretchr/testify/require"
)

func Test_tokens_encrypt_decrypt(t *testing.T) {
	var (
		tkn  = token.NewBearerToken()
		tkn2 = token.NewBearerToken()
	)
	sec, err := keys.NewPrivateKey()
	require.NoError(t, err)

	cred, err := keys.NewPrivateKey()
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(&sec.PrivateKey))

	rawTkn, err := tkn.Marshal()
	require.NoError(t, err)

	data, err := encrypt(cred, cred.PublicKey(), rawTkn)
	require.NoError(t, err)

	rawTkn2, err := decrypt(cred, cred.PublicKey(), data)
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

	sec, err := keys.NewPrivateKey()
	require.NoError(t, err)

	cred, err := keys.NewPrivateKey()
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(&sec.PrivateKey))

	gate := NewGateData(cred.PublicKey(), tkn)
	box, _, err = PackTokens([]*GateData{gate})
	require.NoError(t, err)

	data, err := box.Marshal()
	require.NoError(t, err)

	err = box2.Unmarshal(data)
	require.NoError(t, err)

	tkns, err := box2.GetTokens(cred)
	require.NoError(t, err)

	require.Equal(t, tkn, tkns.BearerToken)
}

func Test_session_token_in_access_box(t *testing.T) {
	var (
		box  *AccessBox
		box2 AccessBox
		tkn  = session.NewToken()
	)

	sec, err := keys.NewPrivateKey()
	require.NoError(t, err)

	cred, err := keys.NewPrivateKey()
	require.NoError(t, err)

	tok := session.NewToken()
	tok.SetContext(session.NewContainerContext())
	uid, err := uuid.New().MarshalBinary()
	require.NoError(t, err)
	tok.SetID(uid)
	tok.SetSessionKey(sec.PublicKey().Bytes())
	require.NoError(t, tkn.Sign(&sec.PrivateKey))

	gate := NewGateData(cred.PublicKey(), token.NewBearerToken())
	gate.SessionToken = tkn
	box, _, err = PackTokens([]*GateData{gate})
	require.NoError(t, err)

	data, err := box.Marshal()
	require.NoError(t, err)

	err = box2.Unmarshal(data)
	require.NoError(t, err)

	tkns, err := box2.GetTokens(cred)
	require.NoError(t, err)

	require.Equal(t, tkn, tkns.SessionToken)
}

func Test_accessbox_multiple_keys(t *testing.T) {
	var (
		box *AccessBox
		tkn = token.NewBearerToken()
	)

	sec, err := keys.NewPrivateKey()
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(&sec.PrivateKey))

	count := 10
	gates := make([]*GateData, 0, count)
	privateKeys := make([]*keys.PrivateKey, 0, count)
	{ // generate keys
		for i := 0; i < count; i++ {
			cred, err := keys.NewPrivateKey()
			require.NoError(t, err)

			gates = append(gates, NewGateData(cred.PublicKey(), tkn))
			privateKeys = append(privateKeys, cred)
		}
	}

	box, _, err = PackTokens(gates)
	require.NoError(t, err)

	for i, k := range privateKeys {
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

	sec, err := keys.NewPrivateKey()
	require.NoError(t, err)

	cred, err := keys.NewPrivateKey()
	require.NoError(t, err)

	wrongCred, err := keys.NewPrivateKey()
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(&sec.PrivateKey))

	gate := NewGateData(cred.PublicKey(), tkn)
	box, _, err = PackTokens([]*GateData{gate})
	require.NoError(t, err)

	_, err = box.GetTokens(wrongCred)
	require.Error(t, err)
}
