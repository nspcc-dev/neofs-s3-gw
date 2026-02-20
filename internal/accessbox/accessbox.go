package accessbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"slices"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
)

const (
	hkdfInfo       = "neofs-s3-gw"
	hkdfSaltLength = 16
)

// Encrypt encrypts data with ephemeral key and gate key.
func Encrypt(owner *keys.PrivateKey, sender *keys.PublicKey, data []byte) ([]byte, error) {
	hkdfSalt := make([]byte, hkdfSaltLength)
	_, _ = rand.Read(hkdfSalt)

	enc, err := getCipher(owner, sender, hkdfSalt)
	if err != nil {
		return nil, fmt.Errorf("get chiper: %w", err)
	}

	nonce := make([]byte, enc.NonceSize())
	_, _ = rand.Read(nonce)

	return slices.Concat(hkdfSalt, enc.Seal(nonce, nonce, data, nil)), nil
}

// Decrypt dencrypts data with ephemeral key and gate key.
func Decrypt(owner *keys.PrivateKey, sender *keys.PublicKey, data []byte) ([]byte, error) {
	if len(data) < hkdfSaltLength {
		return nil, errors.New("invalid data length")
	}

	dec, err := getCipher(owner, sender, data[:hkdfSaltLength])
	if err != nil {
		return nil, fmt.Errorf("get chiper: %w", err)
	}
	data = data[hkdfSaltLength:]

	if ld, ns := len(data), dec.NonceSize(); ld < ns {
		return nil, fmt.Errorf("wrong data size (%d), should be greater than %d", ld, ns)
	}

	nonce, cypher := data[:dec.NonceSize()], data[dec.NonceSize():]
	return dec.Open(nil, nonce, cypher, nil)
}

func generateShared256(prv *keys.PrivateKey, pub *keys.PublicKey) (sk []byte, err error) {
	if prv.PublicKey().Curve != pub.Curve {
		return nil, fmt.Errorf("not equal curves")
	}

	x, _ := pub.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("shared key is point at infinity")
	}

	sk = make([]byte, 32)
	skBytes := x.Bytes()
	copy(sk[len(sk)-len(skBytes):], skBytes)
	return sk, nil
}

func deriveKey(secret []byte, hkdfSalt []byte) ([]byte, error) {
	hash := func() hash.Hash { return sha256.New() }
	key, err := hkdf.Key(hash, secret, hkdfSalt, hkdfInfo, 32)
	return key, err
}

func getCipher(owner *keys.PrivateKey, sender *keys.PublicKey, hkdfSalt []byte) (cipher.AEAD, error) {
	secret, err := generateShared256(owner, sender)
	if err != nil {
		return nil, fmt.Errorf("generate shared key: %w", err)
	}

	key, err := deriveKey(secret, hkdfSalt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes instance: %w", err)
	}

	return cipher.NewGCM(cipherBlock)
}
