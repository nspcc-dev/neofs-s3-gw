package neofs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("should fail", func(t *testing.T) {
		cred, err := New("")
		require.Nil(t, cred)
		require.Error(t, err)
	})

	t.Run("should work as expected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		wif, err := crypto.WIFEncode(key)
		require.NoError(t, err)

		wallet, err := owner.NEO3WalletFromPublicKey(&key.PublicKey)
		require.NoError(t, err)

		own := owner.NewIDFromNeo3Wallet(wallet)

		cred, err := New(wif)
		require.NoError(t, err)
		require.Equal(t, cred.WIF(), wif)
		require.Equal(t, cred.Owner(), own)
		require.Equal(t, cred.PrivateKey(), key)
		require.Equal(t, cred.PublicKey(), &key.PublicKey)
	})
}
