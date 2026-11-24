package accessbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

const numGates = 3

func newGateKeys(t *testing.T) ([]*keys.PrivateKey, []session.Target) {
	gateKeys := make([]*keys.PrivateKey, numGates)
	targets := make([]session.Target, numGates)

	for i := range gateKeys {
		gk, err := keys.NewPrivateKey()
		require.NoError(t, err)
		gateKeys[i] = gk
		targets[i] = session.NewTargetUser(user.NewFromScriptHash(gk.PublicKey().GetScriptHash()))
	}

	return gateKeys, targets
}

func newGates(t *testing.T, targets []session.Target, appData []byte) ([]*GateData, user.ID) {
	issuerKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	issuerSigner := user.NewAutoIDSignerRFC6979(issuerKey.PrivateKey)

	gates := make([]*GateData, numGates)
	for i := range gates {
		var tok session.Token
		tok.SetVersion(session.TokenCurrentVersion)
		tok.SetIssuer(issuerSigner.UserID())
		require.NoError(t, tok.SetSubjects(targets))
		require.NoError(t, tok.SetAppData(appData))
		require.NoError(t, tok.Sign(issuerSigner))

		gates[i] = &GateData{SessionTokenV2: &tok}
	}

	return gates, issuerSigner.UserID()
}

func TestAccessBoxRoundTrip(t *testing.T) {
	gateKeys, targets := newGateKeys(t)
	secret := generateSecret()

	var appData bytes.Buffer
	for _, gk := range gateKeys {
		enc, err := accessbox.EncryptV2(gk.PublicKey(), secret)
		require.NoError(t, err)
		_, err = appData.Write(enc)
		require.NoError(t, err)
	}

	gates, issuer := newGates(t, targets, appData.Bytes())

	box, err := PackTokens(gates)
	require.NoError(t, err)
	require.EqualValues(t, accessBoxVersionHPKE, box.Version)
	// HPKE carries its own ephemeral key in every sealed block.
	require.Empty(t, box.OwnerPublicKey)

	marshaled, err := box.Marshal()
	require.NoError(t, err)

	var box2 AccessBox
	require.NoError(t, box2.Unmarshal(marshaled))

	expectedAccessKey := hex.EncodeToString(secret)
	for i, gk := range gateKeys {
		got, err := box2.GetTokens(gk, nil)
		require.NoError(t, err, "gate %d", i)
		require.NotNil(t, got.SessionTokenV2)
		require.Equal(t, issuer, got.SessionTokenV2.OriginalIssuer())
		require.Equal(t, expectedAccessKey, got.AccessKey)
	}

	// A key not bound to any subject should fail.
	other, err := keys.NewPrivateKey()
	require.NoError(t, err)
	_, err = box2.GetTokens(other, nil)
	require.Error(t, err)

	// A box with an unknown version must be rejected up-front.
	box2.Version = accessBoxVersionCurrent + 1
	_, err = box2.GetTokens(gateKeys[0], nil)
	require.ErrorContains(t, err, "unsupported access box version")
}

type failingResolver struct{}

func (failingResolver) HasUser(string, user.ID) (bool, error) {
	return false, errors.New("resolver failure")
}

// A failure to resolve an NNS subject of a gate token is told apart from an
// unusable box.
func TestGetTokensNNSSubject(t *testing.T) {
	gateKeys, targets := newGateKeys(t)
	targets = append([]session.Target{session.NewTargetNamed("gates.neofs")}, targets...)
	secret := generateSecret()

	appData := make([]byte, accessbox.EncryptedSecretLengthV2)
	for _, gk := range gateKeys {
		enc, err := accessbox.EncryptV2(gk.PublicKey(), secret)
		require.NoError(t, err)
		appData = append(appData, enc...)
	}

	gates, _ := newGates(t, targets, appData)

	box, err := PackTokens(gates)
	require.NoError(t, err)

	for i, gk := range gateKeys {
		_, err := box.GetTokens(gk, failingResolver{})
		require.ErrorIs(t, err, ErrAuthorityCheck, "gate %d", i)

		got, err := box.GetTokens(gk, nil)
		require.NoError(t, err, "gate %d", i)
		require.Equal(t, hex.EncodeToString(secret), got.AccessKey)
	}
}

func generateSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
