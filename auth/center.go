package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/klauspost/compress/zstd"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const authorizationFieldPattern = `AWS4-HMAC-SHA256 Credential=(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request, SignedHeaders=(?P<signed_header_fields>.*), Signature=(?P<v4_signature>.*)`

const emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

// Center is a central app's authentication/authorization management unit.
type Center struct {
	log         *zap.Logger
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
func NewCenter(log *zap.Logger) *Center {
	zstdEncoder, _ := zstd.NewWriter(nil)
	zstdDecoder, _ := zstd.NewReader(nil)
	return &Center{
		log:         log,
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

func (center *Center) packBearerToken(bearerToken *service.BearerTokenMsg) (string, string, error) {
	data, err := bearerToken.Marshal()
	if err != nil {
		return "", "", errors.Wrap(err, "failed to marshal bearer token")
	}
	encryptedKeyID, err := encrypt(center.userAuthKeys.PublicKey, center.compress(data))
	if err != nil {
		return "", "", errors.Wrap(err, "failed to encrypt bearer token bytes")
	}
	accessKeyID := hex.EncodeToString(encryptedKeyID)
	secretAccessKey := hex.EncodeToString(sha256Hash(data))
	return accessKeyID, secretAccessKey, nil
}

func (center *Center) unpackBearerToken(accessKeyID string) (*service.BearerTokenMsg, error) {
	encryptedKeyID, err := hex.DecodeString(accessKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode HEX string")
	}
	compressedKeyID, err := decrypt(center.userAuthKeys.PrivateKey, encryptedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt key ID")
	}
	data, err := center.decompress(compressedKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress key ID")
	}
	bearerToken := new(service.BearerTokenMsg)
	if err := bearerToken.Unmarshal(data); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal embedded bearer token")
	}
	return bearerToken, nil
}

func (center *Center) AuthenticationPassed(request *http.Request) (*service.BearerTokenMsg, error) {
	authHeaderField := request.Header["Authorization"]
	if len(authHeaderField) != 1 {
		return nil, errors.New("unsupported request: wrong length of Authorization header field")
	}
	sms := center.submatcher.getSubmatches(authHeaderField[0])
	if len(sms) != 6 {
		return nil, errors.New("bad Authorization header field")
	}
	bt, err := center.unpackBearerToken(sms["access_key_id"])
	if err != nil {
		center.log.Warn("Failed to unpack bearer token", zap.Error(err))
		//return nil, errors.Wrap(err, "failed to unpack bearer token")
	}
	return bt, nil
}

func readAndReplaceBody(request *http.Request) []byte {
	if request.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(request.Body)
	request.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

func (center *Center) compress(data []byte) []byte {
	return center.zstdEncoder.EncodeAll(data, make([]byte, 0, len(data)))
}

func (center *Center) decompress(data []byte) ([]byte, error) {
	return center.zstdDecoder.DecodeAll(data, nil)
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
