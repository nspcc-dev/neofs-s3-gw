package accessbox

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/stretchr/testify/require"
)

func Test_encrypt_decrypt(t *testing.T) {
	tkn := token.NewBearerToken()
	box := NewBearerBox(tkn)

	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := hcs.Generate(rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	data, err := box.Marshal()
	require.NoError(t, err)

	encrypted, err := encrypt(cred.PrivateKey(), cred.PublicKey(), data)
	require.NoError(t, err)

	decrypted, err := decrypt(cred.PrivateKey(), cred.PublicKey(), encrypted)
	require.NoError(t, err)

	require.Equal(t, data, decrypted)
}

func Test_encrypt_decrypt_step_by_step(t *testing.T) {
	tkn := token.NewBearerToken()
	box := NewBearerBox(tkn)

	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := hcs.Generate(rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	data, err := box.Marshal()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	_, err = cred.PublicKey().WriteTo(buf)
	require.NoError(t, err)

	encrypted, err := encrypt(cred.PrivateKey(), cred.PublicKey(), data)
	require.NoError(t, err)

	length := len(encrypted)
	temp := make([]byte, length+binary.MaxVarintLen64)
	size := binary.PutVarint(temp, int64(length))
	copy(temp[size:], encrypted)
	buf.Write(temp[:length+size])

	sender, err := hcs.NewPublicKeyFromReader(buf)
	require.NoError(t, err)

	require.Equal(t, cred.PublicKey(), sender)

	ln, err := binary.ReadVarint(buf)
	require.NoError(t, err)
	require.Equal(t, int64(length), ln)

	enc := make([]byte, ln)
	n, err := buf.Read(enc)
	require.NoError(t, err)
	require.Equal(t, length, n)
	require.Equal(t, encrypted, enc)

	decrypted, err := decrypt(cred.PrivateKey(), sender, enc)
	require.NoError(t, err)
	require.Equal(t, data, decrypted)
}

func TestSingleKey_AccessBox(t *testing.T) {
	tkn := token.NewBearerToken()
	expect := NewBearerBox(tkn)
	actual := NewBearerBox(nil)

	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := hcs.Generate(rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	data, err := Encode(expect, cred.PrivateKey(), cred.PublicKey())
	require.NoError(t, err)

	require.NoError(t, Decode(data, actual, cred.PrivateKey()))
	require.Equal(t, expect, actual)
}

func TestBearerToken_AccessBox(t *testing.T) {
	tkn := token.NewBearerToken()
	box := NewBearerBox(tkn)
	sec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := hcs.Generate(rand.Reader)
	require.NoError(t, err)

	tkn.SetEACLTable(eacl.NewTable())
	require.NoError(t, tkn.SignToken(sec))

	count := 10
	pubs := make([]hcs.PublicKey, 0, count)
	keys := make([]hcs.PrivateKey, 0, count)
	{ // generate keys
		for i := 0; i < count; i++ {
			cred, err := hcs.Generate(rand.Reader)
			require.NoError(t, err)

			pubs = append(pubs, cred.PublicKey())
			keys = append(keys, cred.PrivateKey())
		}
	}

	buf := new(bytes.Buffer)
	require.NoError(t, NewEncoder(buf, cred.PrivateKey(), pubs...).Encode(box))

	data := buf.Bytes()

	for i := range keys {
		key := keys[i]
		t.Run("try with key "+strconv.Itoa(i), func(t *testing.T) {
			r := bytes.NewReader(data)
			nbx := NewBearerBox(nil)
			require.NoError(t, NewDecoder(r, key).Decode(nbx))
			require.Equal(t, tkn, nbx.Token())
		})
	}

	t.Run("should fail for unknown key", func(t *testing.T) {
		cred, err = hcs.Generate(rand.Reader)
		require.NoError(t, err)

		r := bytes.NewReader(data)
		nbx := NewBearerBox(nil)
		require.EqualError(t, NewDecoder(r, cred.PrivateKey()).Decode(nbx), "chacha20poly1305: message authentication failed")
	})
}
