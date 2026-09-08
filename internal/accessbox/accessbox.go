package accessbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
)

const (
	hkdfInfo       = "neofs-s3-gw"
	hkdfSaltLength = 16

	// EncryptedSecretLengthV1 is the length of a 32-byte secret encrypted with
	// 16 bytes of HKDF salt, 12 bytes of AES-GCM nonce, 32 bytes of ciphertext and 16 bytes of tag.
	// Total is 76.
	EncryptedSecretLengthV1 = hkdfSaltLength + 12 + 32 + 16

	// EncryptedSecretLengthV2 is the length of a 32-byte secret encrypted with [EncryptV2]:
	// 65 bytes of DHKEM(P-256, HKDF-SHA256) encapsulated key, 32 bytes of ciphertext
	// and 16 bytes of tag.
	// Total is 113.
	EncryptedSecretLengthV2 = 65 + 32 + 16
)

// DecryptV1 decrypts data with ephemeral key and gate key.
// Version 1 data is not produced anymore, use [EncryptV2] to encrypt.
func DecryptV1(owner *keys.PrivateKey, sender *keys.PublicKey, data []byte) ([]byte, error) {
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

// EncryptV2 encrypts data for the given gate with HPKE.
func EncryptV2(gate *keys.PublicKey, data []byte) ([]byte, error) {
	pub, err := (*ecdsa.PublicKey)(gate).ECDH()
	if err != nil {
		return nil, fmt.Errorf("gate public key: %w", err)
	}

	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("HPKE public key: %w", err)
	}

	return hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hkdfInfo), data)
}

// DecryptV2 decrypts data sealed for the given gate by [EncryptV2].
func DecryptV2(gate *keys.PrivateKey, data []byte) ([]byte, error) {
	priv, err := gate.ECDH()
	if err != nil {
		return nil, fmt.Errorf("gate private key: %w", err)
	}

	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("HPKE private key: %w", err)
	}

	return hpke.Open(k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hkdfInfo), data)
}
