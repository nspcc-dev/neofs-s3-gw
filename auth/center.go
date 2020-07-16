package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/pkg/errors"
)

const authorizationFieldPattern = `AWS4-HMAC-SHA256 Credential=(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request, SignedHeaders=(?P<signed_header_fields>.*), Signature=(?P<v4_signature>.*)`

// Center is a central app's authentication/authorization management unit.
type Center struct {
	submatcher  *regexpSubmatcher
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
	neofsKeys   struct {
		PrivateKey *ecdsa.PrivateKey
		PublicKey  *ecdsa.PublicKey
	}
	ownerID      refs.OwnerID
	wifString    string
	userAuthKeys struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
	}
}

// NewCenter creates an instance of AuthCenter.
func NewCenter() *Center {
	zstdEncoder, _ := zstd.NewWriter(nil)
	zstdDecoder, _ := zstd.NewReader(nil)
	return &Center{
		submatcher:  &regexpSubmatcher{re: regexp.MustCompile(authorizationFieldPattern)},
		zstdEncoder: zstdEncoder,
		zstdDecoder: zstdDecoder,
	}
}

func (center *Center) SetNeoFSKeys(key *ecdsa.PrivateKey) error {
	publicKey := &key.PublicKey
	oid, err := refs.NewOwnerID(publicKey)
	if err != nil {
		return errors.Wrap(err, "failed to get OwnerID")
	}
	center.neofsKeys.PrivateKey = key
	wif, err := crypto.WIFEncode(key)
	if err != nil {
		return errors.Wrap(err, "failed to get WIF string from given key")
	}
	center.neofsKeys.PublicKey = publicKey
	center.ownerID = oid
	center.wifString = wif
	return nil
}

func (center *Center) GetNeoFSKeyPrivateKey() *ecdsa.PrivateKey {
	return center.neofsKeys.PrivateKey
}

func (center *Center) GetNeoFSKeyPublicKey() *ecdsa.PublicKey {
	return center.neofsKeys.PublicKey
}

func (center *Center) GetOwnerID() refs.OwnerID {
	return center.ownerID
}

func (center *Center) GetWIFString() string {
	return center.wifString
}

func (center *Center) SetUserAuthKeys(key *rsa.PrivateKey) {
	center.userAuthKeys.PrivateKey = key
	center.userAuthKeys.PublicKey = &key.PublicKey
}

func (center *Center) packBearerToken(bearerToken *service.BearerTokenMsg) ([]byte, error) {
	data, err := bearerToken.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal bearer token")
	}
	encryptedKeyID, err := encrypt(center.userAuthKeys.PublicKey, center.compress(data))
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return append(sha256Hash(data), encryptedKeyID...), nil
}

func (center *Center) unpackBearerToken(packedBearerToken []byte) (*service.BearerTokenMsg, error) {
	compressedKeyID := packedBearerToken[32:]
	encryptedKeyID, err := center.decompress(compressedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	keyID, err := decrypt(center.userAuthKeys.PrivateKey, encryptedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt key ID")
	}
	bearerToken := new(service.BearerTokenMsg)
	if err := bearerToken.Unmarshal(keyID); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	return bearerToken, nil
}

func (center *Center) AuthenticationPassed(header http.Header) (*service.BearerTokenMsg, error) {
	authHeaderField := header["Authorization"]
	if len(authHeaderField) != 1 {
		return nil, errors.New("wrong length of Authorization header field")
	}
	sms := center.submatcher.getSubmatches(authHeaderField[0])
	if len(sms) != 6 {
		return nil, errors.New("bad Authorization header field")
	}
	akid := sms["access_key_id"]
	bt, err := center.unpackBearerToken([]byte(akid))
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack bearer token")
	}
	// v4sig := sms["v4_signature"]
	// TODO: Validate V4 signature.
	return bt, nil
}

func (center *Center) compress(data []byte) []byte {
	center.zstdEncoder.Reset(nil)
	var compressedData []byte
	center.zstdEncoder.EncodeAll(data, compressedData)
	return compressedData
}

func (center *Center) decompress(data []byte) ([]byte, error) {
	center.zstdDecoder.Reset(nil)
	var decompressedData []byte
	if _, err := center.zstdDecoder.DecodeAll(data, decompressedData); err != nil {
		return nil, err
	}
	return decompressedData, nil
}

func encrypt(key *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, []byte{})
}

func decrypt(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, key, data, []byte{})
}

func sha256Hash(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func ReadRSAPrivateKeyFromPEMFile(filePath string) (*rsa.PrivateKey, error) {
	kbs, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read file %s", filePath)
	}
	pemBlock, _ := pem.Decode(kbs)
	if pemBlock == nil {
		return nil, errors.Errorf("failed to decode PEM data from file %s", filePath)
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse private key bytes from pem data from file %s", filePath)
	}
	return rsaKey, nil
}

type regexpSubmatcher struct {
	re *regexp.Regexp
}

func (resm *regexpSubmatcher) getSubmatches(target string) map[string]string {
	matches := resm.re.FindStringSubmatch(target)
	l := len(matches)
	submatches := make(map[string]string, l)
	for i, name := range resm.re.SubexpNames() {
		if i > 0 && i <= l {
			submatches[name] = matches[i]
		}
	}
	return submatches
}
