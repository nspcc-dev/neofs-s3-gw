package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	aws_credentials "github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-authmate/accessbox/hcs"
	"github.com/nspcc-dev/neofs-authmate/credentials"
	"github.com/nspcc-dev/neofs-authmate/gates"
	manager "github.com/nspcc-dev/neofs-authmate/neofsmanager"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id_cid>[^/]+)/(?P<access_key_id_oid>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

const emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

// Center is a central app's authentication/authorization management unit.
type Center struct {
	log              *zap.Logger
	submatcher       *regexpSubmatcher
	neofsCredentials *credentials.Credentials
	manager          *manager.Manager
	authKeys         *hcs.X25519Keys
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
	creds, err := credentials.NewFromKey(key)
	if err != nil {
		return err
	}
	center.neofsCredentials = creds
	return nil
}

func (center *Center) GetNeoFSPrivateKey() *ecdsa.PrivateKey {
	return center.neofsCredentials.Key()
}

func (center *Center) GetOwnerID() refs.OwnerID {
	return center.neofsCredentials.OwnerID()
}

func (center *Center) SetAuthKeys(key hcs.X25519PrivateKey) error {
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
	if len(sms1) != 7 {
		return nil, errors.New("bad Authorization header field")
	}
	signedHeaderFieldsNames := strings.Split(sms1["signed_header_fields"], ";")
	if len(signedHeaderFieldsNames) == 0 {
		return nil, errors.New("wrong format of signed headers part")
	}
	signatureDateTime, err := time.Parse("20060102T150405Z", request.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse x-amz-date header field")
	}
	accessKeyID := fmt.Sprintf("%s/%s", sms1["access_key_id_cid"], sms1["access_key_id_oid"])
	bearerToken, secretAccessKey, err := center.fetchBearerToken(accessKeyID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch bearer token")
	}
	otherRequest := request.Clone(context.TODO())
	otherRequest.Header = map[string][]string{}
	for hfn, hfvs := range request.Header {
		for _, shfn := range signedHeaderFieldsNames {
			if strings.EqualFold(hfn, shfn) {
				otherRequest.Header[hfn] = hfvs
			}
		}
	}
	awsCreds := aws_credentials.NewStaticCredentials(accessKeyID, secretAccessKey, "")
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
	return bearerToken, nil
}

func (center *Center) fetchBearerToken(accessKeyID string) (*service.BearerTokenMsg, string, error) {
	akid := new(refs.Address)
	if err := akid.Parse(accessKeyID); err != nil {
		return nil, "", errors.Wrap(err, "failed to parse access key id as refs.Address")
	}
	config := &gates.ObtainingConfig{
		BaseConfig: gates.BaseConfig{
			OperationalCredentials: center.neofsCredentials,
			Manager:                center.manager,
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
	return ioutil.ReadFile(path)
}
