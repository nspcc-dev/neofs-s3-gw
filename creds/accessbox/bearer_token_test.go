package accessbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

func TestTokensEncryptDecrypt(t *testing.T) {
	var (
		tkn  bearer.Token
		tkn2 bearer.Token
	)
	sec, err := keys.NewPrivateKey()
	require.NoError(t, err)

	cred, err := keys.NewPrivateKey()
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.Table{})
	require.NoError(t, tkn.Sign(user.NewAutoIDSignerRFC6979(sec.PrivateKey)))

	data, err := accessbox.Encrypt(cred, cred.PublicKey(), tkn.Marshal())
	require.NoError(t, err)

	rawTkn2, err := accessbox.Decrypt(cred, cred.PublicKey(), data)
	require.NoError(t, err)

	err = tkn2.Unmarshal(rawTkn2)
	require.NoError(t, err)

	require.Equal(t, tkn.Marshal(), tkn2.Marshal())
}

func TestAccessBoxV2RoundTrip(t *testing.T) {
	const numGates = 3

	issuerKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	issuerSigner := user.NewAutoIDSignerRFC6979(issuerKey.PrivateKey)

	ephemeralKey, err := keys.NewPrivateKey()
	require.NoError(t, err)

	secret := generateSecret()

	gateKeys := make([]*keys.PrivateKey, numGates)
	targets := make([]session.Target, numGates)
	var appData bytes.Buffer
	for i := range gateKeys {
		gk, err := keys.NewPrivateKey()
		require.NoError(t, err)
		gateKeys[i] = gk
		targets[i] = session.NewTargetUser(user.NewFromScriptHash(gk.PublicKey().GetScriptHash()))

		enc, err := accessbox.Encrypt(ephemeralKey, gk.PublicKey(), secret)
		require.NoError(t, err)
		_, err = appData.Write(enc)
		require.NoError(t, err)
	}

	gates := make([]*GateData, numGates)
	for i := range gates {
		var tok session.Token
		tok.SetVersion(session.TokenCurrentVersion)
		tok.SetIssuer(issuerSigner.UserID())
		require.NoError(t, tok.SetSubjects(targets))
		require.NoError(t, tok.SetAppData(appData.Bytes()))
		require.NoError(t, tok.Sign(issuerSigner))

		gates[i] = &GateData{SessionTokenV2: &tok}
	}

	box, _, err := PackTokens(gates, ephemeralKey, secret)
	require.NoError(t, err)

	marshaled, err := box.Marshal()
	require.NoError(t, err)

	var box2 AccessBox
	require.NoError(t, box2.Unmarshal(marshaled))

	expectedAccessKey := hex.EncodeToString(secret)
	for i, gk := range gateKeys {
		got, err := box2.GetTokens(gk, nil)
		require.NoError(t, err, "gate %d", i)
		require.NotNil(t, got.SessionTokenV2)
		require.Equal(t, issuerSigner.UserID(), got.SessionTokenV2.OriginalIssuer())
		require.Equal(t, expectedAccessKey, got.AccessKey)
	}

	// A key not bound to any subject should fail.
	other, err := keys.NewPrivateKey()
	require.NoError(t, err)
	_, err = box2.GetTokens(other, nil)
	require.Error(t, err)

	// A box with an unknown version must be rejected up-front.
	box2.Version = accessBoxVersionSessionV2 + 1
	_, err = box2.GetTokens(gateKeys[0], nil)
	require.ErrorContains(t, err, "unsupported access box version")
}

func generateSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
