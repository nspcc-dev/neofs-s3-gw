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
	"path/filepath"

	"github.com/pkg/errors"
)

const (
	// PathToUserAuthPrivateKeyFile is a linux-specific predefined path
	// to a persisted RSA private key for authenticating at S3 server.
	PathToUserAuthPrivateKeyFile = "/etc/neofs/1.pem"
	// PathToNeoFSECDSAPrivateKeyFile is a linux-specific predefined path
	// to a persisted ECDSA private key for accessing NeoFS network.
	PathToNeoFSECDSAPrivateKeyFile = "/etc/neofs/2.pem"
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

var globalEnclave *secureEnclave

func init() {
	var err error
	globalEnclave, err = newSecureEnclave()
	if err != nil {
		panic("failed to initialize secure enclave")
	}
}

type secureEnclave struct {
	signatureKeys  map[signatureKeyName]signatureKeyPair
	encryptionKeys map[encryptionKeyName]encryptionKeyPair
}

func newSecureEnclave() (*secureEnclave, error) {
	var (
		pathToKey1, pathToKey2 string
		key1                   *rsa.PrivateKey
		key2                   *ecdsa.PrivateKey
	)
	// FIXME: Get private keys properly.
	if _debug {
		ep, _ := os.Executable()
		base := filepath.Dir(ep)
		pathToKey1, pathToKey2 = filepath.Join(base, "1.pem"), filepath.Join(base, "2.pem")
	} else {
		pathToKey1, pathToKey2 = PathToUserAuthPrivateKeyFile, PathToNeoFSECDSAPrivateKeyFile
	}
	if key1bs, err := ioutil.ReadFile(pathToKey1); err != nil {
		// No file found.
		if os.IsNotExist(err) {
			if key1, err = rsa.GenerateKey(rand.Reader, gatewayEncryptionKeySize); err != nil {
				return nil, errors.Wrap(err, "failed to generate RSA key")
			}
			key1bs := x509.MarshalPKCS1PrivateKey(key1)
			data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key1bs})
			if err := ioutil.WriteFile(pathToKey1, data, 0o600); err != nil {
				return nil, errors.Wrapf(err, "failed to write file %s", pathToKey1)
			}
		} else {
			return nil, errors.Wrapf(err, "failed to open file %s", pathToKey1)
		}
	} else {
		pemBlock, _ := pem.Decode(key1bs)
		if pemBlock == nil {
			return nil, errors.Errorf("failed to decode PEM data from file %s", pathToKey1)
		}
		key1, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse private key bytes from pem data from file %s", pathToKey1)
		}
	}
	if key2bs, err := ioutil.ReadFile(pathToKey2); err != nil {
		// No file found.
		if os.IsNotExist(err) {
			if key2, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
				return nil, errors.Wrap(err, "failed to generate ECDSA key")
			}
			key2bs, err := x509.MarshalECPrivateKey(key2)
			if err != nil {
				return nil, errors.New("failed to marshal ECDSA private key")
			}
			data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key2bs})
			if err := ioutil.WriteFile(pathToKey2, data, 0o600); err != nil {
				return nil, errors.Wrapf(err, "failed to write file %s", pathToKey2)
			}
		} else {
			return nil, errors.Wrapf(err, "failed to open file %s", pathToKey2)
		}
	} else {
		pemBlock, _ := pem.Decode(key2bs)
		if pemBlock == nil {
			return nil, errors.Errorf("failed to decode PEM data from file %s", pathToKey2)
		}
		key2, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse private key bytes from pem data from file %s", pathToKey2)
		}
	}
	return &secureEnclave{
		encryptionKeys: map[encryptionKeyName]encryptionKeyPair{
			gateUserAuthKey: {key1, &key1.PublicKey},
		},
		signatureKeys: map[signatureKeyName]signatureKeyPair{
			gateNeoFSECDSAKey: {key2, &key2.PublicKey},
		},
	}, nil
}

func (se *secureEnclave) Encrypt(keyName encryptionKeyName, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, se.encryptionKeys[keyName].PublicKey, data, []byte{})
}

func (se *secureEnclave) Decrypt(keyName encryptionKeyName, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, se.encryptionKeys[keyName].PrivateKey, data, []byte{})
}
