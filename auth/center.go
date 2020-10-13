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

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-authmate/accessbox/hcs"
	"github.com/nspcc-dev/neofs-authmate/agents/s3"
	manager "github.com/nspcc-dev/neofs-authmate/manager/neofs"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id_cid>[^/]+)/(?P<access_key_id_oid>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

type (
	Center struct {
		man *manager.Manager
		reg *regexpSubmatcher

		keys *hcs.X25519Keys
	}

	Params struct {
		Timeout time.Duration

		Log *zap.Logger
		Con manager.Connector

		GAKey *hcs.X25519Keys
		NFKey *ecdsa.PrivateKey
	}
)

// New creates an instance of AuthCenter.
func New(ctx context.Context, p *Params) (*Center, error) {
	m, err := manager.New(ctx,
		manager.WithKey(p.NFKey),
		manager.WithLogger(p.Log),
		manager.WithConnector(p.Con))

	if err != nil {
		return nil, err
	}
	return &Center{
		man: m,
		reg: &regexpSubmatcher{re: authorizationFieldRegexp},

		keys: p.GAKey,
	}, nil
}

func (center *Center) AuthenticationPassed(request *http.Request) (*token.BearerToken, error) {
	queryValues := request.URL.Query()
	if queryValues.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return nil, errors.New("pre-signed form of request is not supported")
	}
	authHeaderField := request.Header["Authorization"]
	if len(authHeaderField) != 1 {
		return nil, errors.New("unsupported request: wrong length of Authorization header field")
	}
	sms1 := center.reg.getSubmatches(authHeaderField[0])
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
	res, err := s3.NewAgent(center.man).ObtainSecret(request.Context(), center.keys, accessKeyID)
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
	awsCreds := credentials.NewStaticCredentials(accessKeyID, res.SecretAccessKey, "")
	signer := v4.NewSigner(awsCreds)
	body, err := readAndKeepBody(request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read out request body")
	}
	_, err = signer.Sign(otherRequest, body, sms1["service"], sms1["region"], signatureDateTime)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign temporary HTTP request")
	}
	sms2 := center.reg.getSubmatches(otherRequest.Header.Get("Authorization"))
	if sms1["v4_signature"] != sms2["v4_signature"] {
		return nil, errors.Wrap(err, "failed to pass authentication procedure")
	}
	return res.BearerToken, nil
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
