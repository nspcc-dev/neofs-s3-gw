package auth

import (
	"bytes"
	"crypto/ecdsa"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-authmate/accessbox/hcs"
	"github.com/nspcc-dev/neofs-authmate/gates"
	manager "github.com/nspcc-dev/neofs-authmate/neofsmanager"
	crypto "github.com/nspcc-dev/neofs-crypto"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

const emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

// Center is a central app's authentication/authorization management unit.
type Center struct {
	log        *zap.Logger
	submatcher *regexpSubmatcher
	neofsKeys  struct {
		PrivateKey *ecdsa.PrivateKey
		PublicKey  *ecdsa.PublicKey
	}
	ownerID   refs.OwnerID
	wifString string
	manager   *manager.Manager
	authKeys  *hcs.X25519Keys
}

// NewCenter creates an instance of AuthCenter.
func NewCenter(log *zap.Logger, neofsNodeAddress string) (*Center, error) {
	m, err := manager.NewManager(neofsNodeAddress)
	if err != nil {
		return nil, err
	}
	return &Center{
		log:        log,
		submatcher: &regexpSubmatcher{re: authorizationFieldRegexp},
		manager:    m,
	}, nil
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

func (center *Center) GetNeoFSPrivateKey() *ecdsa.PrivateKey {
	return center.neofsKeys.PrivateKey
}

func (center *Center) GetNeoFSPublicKey() *ecdsa.PublicKey {
	return center.neofsKeys.PublicKey
}

func (center *Center) GetOwnerID() refs.OwnerID {
	return center.ownerID
}

func (center *Center) GetWIFString() string {
	return center.wifString
}

func (center *Center) SetUserAuthKeys(key hcs.X25519PrivateKey) error {
	keys, err := hcs.NewKeys(key)
	if err != nil {
		return err
	}
	center.authKeys = keys
	return nil
}

func (center *Center) AuthenticationPassed(request *http.Request) (*service.BearerTokenMsg, error) {
	queryValues := request.URL.Query()
	if queryValues.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return nil, errors.New("pre-signed form of request is not supported")
	}
	authHeaderField := request.Header["Authorization"]
	if len(authHeaderField) != 1 {
		return nil, errors.New("unsupported request: wrong length of Authorization header field")
	}
	sms1 := center.submatcher.getSubmatches(authHeaderField[0])
	if len(sms1) != 6 {
		return nil, errors.New("bad Authorization header field")
	}
	signedHeaderFieldsNames := strings.Split(sms1["signed_header_fields"], ";")
	if len(signedHeaderFieldsNames) == 0 {
		return nil, errors.New("wrong format of signed headers part")
	}
	// signatureDateTime, err := time.Parse("20060102T150405Z", request.Header.Get("X-Amz-Date"))
	// if err != nil {
	// 	return nil, errors.Wrap(err, "failed to parse x-amz-date header field")
	// }

	accessKeyID := sms1["access_key_id"]
	bearerToken, _, err := center.fetchBearerToken(accessKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch bearer token")
	}

	// Disable verification of S3 signature for arrival of the new auth scheme.
	/*
		otherRequest := request.Clone(context.TODO())
		otherRequest.Header = map[string][]string{}
		for hfn, hfvs := range request.Header {
			for _, shfn := range signedHeaderFieldsNames {
				if strings.EqualFold(hfn, shfn) {
					otherRequest.Header[hfn] = hfvs
				}
			}
		}
		awsCreds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
		signer := v4.NewSigner(awsCreds)
		body, err := readAndKeepBody(request)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read out request body")
		}
		_, err = signer.Sign(otherRequest, body, sms1["service"], sms1["region"], signatureDateTime)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign temporary HTTP request")
		}
		sms2 := center.submatcher.getSubmatches(otherRequest.Header.Get("Authorization"))
		if sms1["v4_signature"] != sms2["v4_signature"] {
			return nil, errors.Wrap(err, "failed to pass authentication procedure")
		}
	*/
	return bearerToken, nil
}

func (center *Center) fetchBearerToken(accessKeyID string) (*service.BearerTokenMsg, string, error) {
	// TODO: Turn it into getting bearer token from NeoFS node later on.
	// accessKeyID = "051d729a102513387b63f2f07a5cd45ca3158b273646527916cc3f705fa0006b249e038f4e4b4986d85b18358da8692819ef6e35063e91efce17da32d956ad9e48d2674f0cab2bd5ff27b49cb9a1b0e71eb73d330b6cd8f23e85252e55afe992765b2983ee2bafc57079221fdc8e48a3f5d8b0be87a259fd12c6afd59e3ec748c8677a4211c8d6ec7b67008a006f526b22a8536effe8ecb6581ea16d7f9358ede53dddf36fb589ab9a829b81d9c69d19a4b9d1ac58d5e9311e3608eb233475bfc47a02633c5611d1bb3b9450ef00b2490924be5f3375e3eb4b6ed2f23906f183c213e77c19ec5c62b3be3a5a5b526851ea674c613b542c2861fd4a5178b65d8df8899a05b25db8b9e15f5e257467044e41b69144fe4b802aff2a56c8960e5e3c7eb004d41a6d873f927db43ed047171f36cda5be080e0df2ddfe15edb423b41491559a7a5cc70932566cdd71058913abb0a68d3c1ac50586f0a48b02e1cea24ca8a2010d5495dbc5daf0575413c06542a16288664104ad06289a5b2bf119071171562dcdc05d6b9260df2fc676540fc1d836c36f77a090cc5ce52b930f74ae625d53e1a80b7a59aa2d85e2f188c131de5739bf0e49e6d5f081e757f2b0d85a8264dfb66c4400bcd4727d7c21eca92c138d975fe51f986e80ec32ba13e8850c82dd813cd45640caa303555e0759d0d111dac6cc39cbe711dd56dc8f01a6022635"
	// secretAccessKey := "12775ab859000dd87b3c7586146f465efc73bbbd33ac3b36f2ab2b061df15f7b"
	// bearerToken, _, err := center.unpackBearerToken(accessKeyID)
	// if err != nil {
	// 	return nil, "", errors.Wrap(err, "failed to fetch bearer token")
	// }
	akid := new(refs.Address)
	if err := akid.Parse(accessKeyID); err != nil {
		return nil, "", errors.Wrap(err, "failed to parse access key id as refs.Address")
	}
	config := &gates.ObtainingConfig{
		BaseConfig: gates.BaseConfig{
			OperationalCredentials: nil,
			Manager:                nil,
		},
		GateKeys:      center.authKeys,
		SecretAddress: akid,
	}
	res, err := gates.ObtainSecret(config)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to obtain secret")
	}
	return res.BearerToken, res.SecretAccessKey, nil
}

// TODO: Make this write into a smart buffer backed by a file on a fast drive.
func readAndKeepBody(request *http.Request) (*bytes.Reader, error) {
	if request.Body == nil {
		var r bytes.Reader
		return &r, nil
	}
	payload, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return bytes.NewReader(payload), nil
}

func LoadGateAuthPrivateKey(path string) (hcs.X25519PrivateKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// FIXME: Rework when DecodeKeysFromBytes will arrive.
	key := string(bytes)
	privateKey, _, err := hcs.DecodeKeys(&key, nil)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
