package accessbox_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	"github.com/stretchr/testify/require"
)

func newSecret() []byte {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return secret
}

func TestDecryptV1(t *testing.T) {
	// Version 1 data is not produced anymore, this vector was encrypted by the
	// removed version 1 Encrypt.
	const (
		gateHex   = "17297cf36cfe261dcbce0b44dbed89ae2cadd792fff2b789df311c27cd454c05"
		senderHex = "031ba71aeb3430d86c4a9ee58f0d364a348ab9d869d364a078f68bce491bbe5c80"
		secretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		encHex    = "f432a89e4dce97140d3d8c0bef3be651398918cce53bbafdd7df239009205acee2f3d5f3b1c8b37b6c868d3e1365d2f3718dde1ba16363fd95afedf7956dca313cf045ff5fe6c2f99694e698"
	)

	gate, err := keys.NewPrivateKeyFromHex(gateHex)
	require.NoError(t, err)

	sender, err := keys.NewPublicKeyFromString(senderHex)
	require.NoError(t, err)

	enc, err := hex.DecodeString(encHex)
	require.NoError(t, err)
	require.Len(t, enc, accessbox.EncryptedSecretLengthV1)

	got, err := accessbox.DecryptV1(gate, sender, enc)
	require.NoError(t, err)
	require.Equal(t, secretHex, hex.EncodeToString(got))

	other, err := keys.NewPrivateKey()
	require.NoError(t, err)

	_, err = accessbox.DecryptV1(other, sender, enc)
	require.Error(t, err)
}

func TestEncryptDecryptV2(t *testing.T) {
	gate, err := keys.NewPrivateKey()
	require.NoError(t, err)

	secret := newSecret()

	enc, err := accessbox.EncryptV2(gate.PublicKey(), secret)
	require.NoError(t, err)
	require.Len(t, enc, accessbox.EncryptedSecretLengthV2)

	got, err := accessbox.DecryptV2(gate, enc)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	other, err := keys.NewPrivateKey()
	require.NoError(t, err)

	_, err = accessbox.DecryptV2(other, enc)
	require.Error(t, err)
}
