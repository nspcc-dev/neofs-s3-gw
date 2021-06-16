package accessbox

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/nspcc-dev/neofs-api-go/pkg/session"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
)

type tokenInterface interface {
	Marshal(bs ...[]byte) ([]byte, error)
	Unmarshal([]byte) error
}

// Marshal returns the wire-format of AccessBox.
func (x *AccessBox) Marshal() ([]byte, error) {
	return proto.Marshal(x)
}

// Unmarshal parses the wire-format message and put data to x.
func (x *AccessBox) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, x)
}

// PackTokens adds a bearer and session tokens to BearerTokens and SessionToken lists respectively.
// Session token can be nil.
func PackTokens(bearer *token.BearerToken, sess *session.Token, keys ...*ecdsa.PublicKey) (*AccessBox, *ecdsa.PrivateKey, error) {
	box := &AccessBox{}
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	box.OwnerPublicKey = crypto.MarshalPublicKey(&ephemeralKey.PublicKey)

	if err := box.addToken(bearer, &box.BearerTokens, ephemeralKey, keys...); err != nil {
		return nil, nil, fmt.Errorf("failed to add bearer token to accessbox: %w", err)
	}
	if sess != nil {
		if err := box.addToken(sess, &box.SessionTokens, ephemeralKey, keys...); err != nil {
			return nil, nil, fmt.Errorf("failed to add session token to accessbox: %w", err)
		}
	}

	return box, ephemeralKey, err
}

// GetBearerToken returns bearer token from AccessBox.
func (x *AccessBox) GetBearerToken(owner *ecdsa.PrivateKey) (*token.BearerToken, error) {
	sender := crypto.UnmarshalPublicKey(x.OwnerPublicKey)
	ownerKey := crypto.MarshalPublicKey(&owner.PublicKey)
	for _, data := range x.BearerTokens {
		if !bytes.Equal(data.GatePublicKey, ownerKey) {
			continue
		}
		tkn := token.NewBearerToken()
		if err := decodeToken(data.Token, tkn, owner, sender); err != nil {
			return nil, fmt.Errorf("failed to decode bearer token: %w", err)
		}
		return tkn, nil
	}

	return nil, fmt.Errorf("no bearer token for key  %x was found", ownerKey)
}

// GetSessionToken returns session token from AccessBox.
func (x *AccessBox) GetSessionToken(owner *ecdsa.PrivateKey) (*session.Token, error) {
	sender := crypto.UnmarshalPublicKey(x.OwnerPublicKey)
	ownerKey := crypto.MarshalPublicKey(&owner.PublicKey)
	for _, data := range x.SessionTokens {
		if !bytes.Equal(data.GatePublicKey, ownerKey) {
			continue
		}
		tkn := session.NewToken()

		if err := decodeToken(data.Token, tkn, owner, sender); err != nil {
			return nil, fmt.Errorf("failed to decode session token: %w", err)
		}
		return tkn, nil
	}

	return nil, fmt.Errorf("no session token for key  %x was found", ownerKey)
}

func (x *AccessBox) addToken(tkn tokenInterface, list *[]*AccessBox_Token, owner *ecdsa.PrivateKey, keys ...*ecdsa.PublicKey) error {
	for i, sender := range keys {
		data, err := encodeToken(tkn, owner, sender)
		if err != nil {
			return fmt.Errorf("%w, sender = %d", err, i)
		}
		*list = append(*list, newToken(data, crypto.MarshalPublicKey(sender)))
	}
	return nil
}

func newToken(data []byte, key []byte) *AccessBox_Token {
	res := new(AccessBox_Token)
	res.Token = data
	res.GatePublicKey = key
	return res
}

func encodeToken(tkn tokenInterface, owner *ecdsa.PrivateKey, sender *ecdsa.PublicKey) ([]byte, error) {
	data, err := tkn.Marshal()
	if err != nil {
		return nil, err
	}

	encrypted, err := encrypt(owner, sender, data)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func decodeToken(data []byte, tkn tokenInterface, owner *ecdsa.PrivateKey, sender *ecdsa.PublicKey) error {
	decoded, err := decrypt(owner, sender, data)
	if err != nil {
		return err
	}

	err = tkn.Unmarshal(decoded)
	if err != nil {
		return err
	}

	return nil
}

func generateShared256(prv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (sk []byte, err error) {
	if prv.PublicKey.Curve != pub.Curve {
		return nil, fmt.Errorf("not equal curves")
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("shared key is point at infinity")
	}

	sk = make([]byte, 32)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

func deriveKey(secret []byte) ([]byte, error) {
	hash := sha256.New
	kdf := hkdf.New(hash, secret, nil, nil)
	key := make([]byte, 32)
	_, err := io.ReadFull(kdf, key)
	return key, err
}

func encrypt(owner *ecdsa.PrivateKey, sender *ecdsa.PublicKey, data []byte) ([]byte, error) {
	enc, err := getCipher(owner, sender)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, enc.NonceSize(), enc.NonceSize()+len(data)+enc.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return enc.Seal(nonce, nonce, data, nil), nil
}

func decrypt(owner *ecdsa.PrivateKey, sender *ecdsa.PublicKey, data []byte) ([]byte, error) {
	dec, err := getCipher(owner, sender)
	if err != nil {
		return nil, err
	}

	if ld, ns := len(data), dec.NonceSize(); ld < ns {
		return nil, fmt.Errorf("wrong data size (%d), should be greater than %d", ld, ns)
	}

	nonce, cypher := data[:dec.NonceSize()], data[dec.NonceSize():]
	return dec.Open(nil, nonce, cypher, nil)
}

func getCipher(owner *ecdsa.PrivateKey, sender *ecdsa.PublicKey) (cipher.AEAD, error) {
	secret, err := generateShared256(owner, sender)
	if err != nil {
		return nil, err
	}

	key, err := deriveKey(secret)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
