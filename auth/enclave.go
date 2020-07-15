package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

const (
	gatewayEncryptionKeySize = 4096
)

const (
	_ encryptionKeyName = iota
	// Indicates that the key is used to encrypt
	// a bearer token to pass auth procedure.
	gateUserAuthKey
)

const (
	_ signatureKeyName = iota
	// Indicates that the key is a NeoFS ECDSA key.
	gateNeoFSECDSAKey
	// Indicates that the key is a NeoFS Ed25519 key.
	gateNeoFSEd25519Key
)

type (
	signatureKeyName  byte
	encryptionKeyName byte
)

type (
	signatureKeyPair struct {
		PrivateKey *ecdsa.PrivateKey
		PublicKey  *ecdsa.PublicKey
	}

	encryptionKeyPair struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
	}
)

type secureEnclave struct {
	signatureKeys  map[signatureKeyName]signatureKeyPair
	encryptionKeys map[encryptionKeyName]encryptionKeyPair
}

func newSecureEnclave(pathToRSAKey, pathToECDSAKey string) (*secureEnclave, error) {
	var (
		rsaKey   *rsa.PrivateKey
		ecdsaKey *ecdsa.PrivateKey
	)
	if key1bs, err := ioutil.ReadFile(pathToRSAKey); err != nil {
		// No file found.
		if os.IsNotExist(err) {
			if rsaKey, err = rsa.GenerateKey(rand.Reader, gatewayEncryptionKeySize); err != nil {
				return nil, errors.Wrap(err, "failed to generate RSA key")
			}
			key1bs := x509.MarshalPKCS1PrivateKey(rsaKey)
			data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key1bs})
			if err := ioutil.WriteFile(pathToRSAKey, data, 0o600); err != nil {
				return nil, errors.Wrapf(err, "failed to write file %s", pathToRSAKey)
			}
		} else {
			return nil, errors.Wrapf(err, "failed to open file %s", pathToRSAKey)
		}
	} else {
		pemBlock, _ := pem.Decode(key1bs)
		if pemBlock == nil {
			return nil, errors.Errorf("failed to decode PEM data from file %s", pathToRSAKey)
		}
		rsaKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse private key bytes from pem data from file %s", pathToRSAKey)
		}
	}
	if key2bs, err := ioutil.ReadFile(pathToECDSAKey); err != nil {
		// No file found.
		if os.IsNotExist(err) {
			if ecdsaKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
				return nil, errors.Wrap(err, "failed to generate ECDSA key")
			}
			key2bs, err := x509.MarshalECPrivateKey(ecdsaKey)
			if err != nil {
				return nil, errors.New("failed to marshal ECDSA private key")
			}
			data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key2bs})
			if err := ioutil.WriteFile(pathToECDSAKey, data, 0o600); err != nil {
				return nil, errors.Wrapf(err, "failed to write file %s", pathToECDSAKey)
			}
		} else {
			return nil, errors.Wrapf(err, "failed to open file %s", pathToECDSAKey)
		}
	} else {
		pemBlock, _ := pem.Decode(key2bs)
		if pemBlock == nil {
			return nil, errors.Errorf("failed to decode PEM data from file %s", pathToECDSAKey)
		}
		ecdsaKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse private key bytes from pem data from file %s", pathToECDSAKey)
		}
	}
	return &secureEnclave{
		encryptionKeys: map[encryptionKeyName]encryptionKeyPair{
			gateUserAuthKey: {rsaKey, &rsaKey.PublicKey},
		},
		signatureKeys: map[signatureKeyName]signatureKeyPair{
			gateNeoFSECDSAKey: {ecdsaKey, &ecdsaKey.PublicKey},
		},
	}, nil
}

func (se *secureEnclave) Encrypt(keyName encryptionKeyName, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, se.encryptionKeys[keyName].PublicKey, data, []byte{})
}

func (se *secureEnclave) Decrypt(keyName encryptionKeyName, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, se.encryptionKeys[keyName].PrivateKey, data, []byte{})
}
