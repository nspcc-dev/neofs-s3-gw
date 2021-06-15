package accessbox

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/nspcc-dev/neofs-api-go/pkg/session"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
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

// AddBearerToken adds a bearer token to BearerTokens list.
func (x *AccessBox) AddBearerToken(tkn *token.BearerToken, owner hcs.PrivateKey, keys ...hcs.PublicKey) error {
	if x.OwnerPublicKey == nil {
		return fmt.Errorf("owner's public key is nil")
	}
	// restriction to rewrite token for the second time
	if len(x.BearerTokens) > 0 {
		return fmt.Errorf("bearer token is already set")
	}
	return x.addToken(tkn, &x.BearerTokens, owner, keys...)
}

// AddSessionToken adds a session token to SessionTokens list.
func (x *AccessBox) AddSessionToken(tkn *session.Token, owner hcs.PrivateKey, keys ...hcs.PublicKey) error {
	if x.OwnerPublicKey == nil {
		return fmt.Errorf("owner's public key is nil")
	}
	//restriction to rewrite token for the second time
	if len(x.SessionTokens) > 0 {
		return fmt.Errorf("bearer token is already set")
	}
	return x.addToken(tkn, &x.SessionTokens, owner, keys...)
}

// SetOwnerPublicKey sets a public key of an issuer.
func (x *AccessBox) SetOwnerPublicKey(key hcs.PublicKey) {
	x.OwnerPublicKey = key.Bytes()
}

// GetBearerToken returns bearer token from AccessBox.
func (x *AccessBox) GetBearerToken(owner hcs.PrivateKey) (*token.BearerToken, error) {
	sender, err := hcs.PublicKeyFromBytes(x.OwnerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load owner public key from AccessBox: %w", err)
	}
	for _, data := range x.BearerTokens {
		if !bytes.Equal(data.GatePublicKey, owner.PublicKey().Bytes()) {
			continue
		}
		tkn := token.NewBearerToken()
		if err := decodeToken(data.Token, tkn, owner, sender); err != nil {
			return nil, fmt.Errorf("failed to decode bearer token: %w", err)
		}
		return tkn, nil
	}

	return nil, fmt.Errorf("no bearer token for key  %s was found", owner.String())
}

// GetSessionToken returns session token from AccessBox.
func (x *AccessBox) GetSessionToken(owner hcs.PrivateKey) (*session.Token, error) {
	sender, err := hcs.PublicKeyFromBytes(x.OwnerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load owner public key from AccessBox: %w", err)
	}
	for _, data := range x.SessionTokens {
		if !bytes.Equal(data.GatePublicKey, owner.PublicKey().Bytes()) {
			continue
		}
		tkn := session.NewToken()

		if err := decodeToken(data.Token, tkn, owner, sender); err != nil {
			return nil, fmt.Errorf("failed to decode session token: %w", err)
		}
		return tkn, nil
	}

	return nil, fmt.Errorf("no session token for key  %s was found", owner.String())
}

func (x *AccessBox) addToken(tkn tokenInterface, list *[]*AccessBox_Token, owner hcs.PrivateKey, keys ...hcs.PublicKey) error {
	for i, sender := range keys {
		data, err := encodeToken(tkn, owner, sender)
		if err != nil {
			return fmt.Errorf("%w, sender = %d", err, i)
		}
		*list = append(*list, newToken(data, sender.Bytes()))
	}
	return nil
}

func newToken(data []byte, key []byte) *AccessBox_Token {
	res := new(AccessBox_Token)
	res.Token = data
	res.GatePublicKey = key
	return res
}

func encodeToken(tkn tokenInterface, owner hcs.PrivateKey, sender hcs.PublicKey) ([]byte, error) {
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

func decodeToken(data []byte, tkn tokenInterface, owner hcs.PrivateKey, sender hcs.PublicKey) error {
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

func encrypt(owner hcs.PrivateKey, sender hcs.PublicKey, data []byte) ([]byte, error) {
	key, err := curve25519.X25519(owner.Bytes(), sender.Bytes())
	if err != nil {
		return nil, err
	}

	enc, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, enc.NonceSize(), enc.NonceSize()+len(data)+enc.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return enc.Seal(nonce, nonce, data, nil), nil
}

func decrypt(owner hcs.PrivateKey, sender hcs.PublicKey, data []byte) ([]byte, error) {
	sb := sender.Bytes()

	key, err := curve25519.X25519(owner.Bytes(), sb)
	if err != nil {
		return nil, err
	}

	dec, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if ld, ns := len(data), dec.NonceSize(); ld < ns {
		return nil, fmt.Errorf("wrong data size (%d), should be greater than %d", ld, ns)
	}

	nonce, cypher := data[:dec.NonceSize()], data[dec.NonceSize():]
	return dec.Open(nil, nonce, cypher, nil)
}
