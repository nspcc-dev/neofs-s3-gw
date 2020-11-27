package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	sdk "github.com/nspcc-dev/cdn-neofs-sdk"
	"github.com/nspcc-dev/cdn-neofs-sdk/creds/bearer"
	"github.com/nspcc-dev/cdn-neofs-sdk/creds/hcs"
	"github.com/nspcc-dev/cdn-neofs-sdk/creds/s3"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id_cid>[^/]+)/(?P<access_key_id_oid>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

type (
	Center interface {
		Authenticate(request *http.Request) (*token.BearerToken, error)
	}

	center struct {
		reg *regexpSubmatcher
		cli bearer.Credentials
	}

	Params struct {
		Client     sdk.Client
		Logger     *zap.Logger
		Credential hcs.Credentials
	}

	prs int
)

func (p prs) Read(_ []byte) (n int, err error) {
	panic("implement me")
}

func (p prs) Seek(_ int64, _ int) (int64, error) {
	panic("implement me")
}

var _ io.ReadSeeker = prs(0)

// New creates an instance of AuthCenter.
func New(obj sdk.ObjectClient, key hcs.PrivateKey) Center {
	return &center{
		cli: bearer.New(obj, key),
		reg: &regexpSubmatcher{re: authorizationFieldRegexp},
	}
}

func (c *center) Authenticate(r *http.Request) (*token.BearerToken, error) {
	queryValues := r.URL.Query()
	if queryValues.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return nil, errors.New("pre-signed form of request is not supported")
	}

	authHeaderField := r.Header["Authorization"]
	if len(authHeaderField) != 1 {
		return nil, errors.New("unsupported request: wrong length of Authorization header field")
	}

	// { // to debug request
	// 	data, _ := httputil.DumpRequest(r, false)
	// 	fmt.Println(string(data))
	// }

	sms1 := c.reg.getSubmatches(authHeaderField[0])
	if len(sms1) != 7 {
		return nil, errors.New("bad Authorization header field")
	}

	signedHeaderFieldsNames := strings.Split(sms1["signed_header_fields"], ";")
	if len(signedHeaderFieldsNames) == 0 {
		return nil, errors.New("wrong format of signed headers part")
	}

	signatureDateTime, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse x-amz-date header field")
	}

	accessKeyID := fmt.Sprintf("%s/%s", sms1["access_key_id_cid"], sms1["access_key_id_oid"])

	address := object.NewAddress()
	if err = address.Parse(accessKeyID); err != nil {
		return nil, errors.Wrapf(err, "could not parse AccessBox address: %s", accessKeyID)
	}

	tkn, err := c.cli.Get(r.Context(), address)
	if err != nil {
		return nil, err
	}

	secret, err := s3.SecretAccessKey(tkn)
	if err != nil {
		return nil, err
	}

	otherRequest := r.Clone(context.TODO())
	otherRequest.Header = map[string][]string{}

	for hfn, hfvs := range r.Header {
		for _, shfn := range signedHeaderFieldsNames {
			if strings.EqualFold(hfn, shfn) {
				otherRequest.Header[hfn] = hfvs
			}
		}
	}

	awsCreds := credentials.NewStaticCredentials(accessKeyID, secret, "")
	signer := v4.NewSigner(awsCreds)

	// body, err := readAndKeepBody(r)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "failed to read out request body")
	// }
	//
	// _ = body

	// body not required
	if _, err := signer.Sign(otherRequest, nil, sms1["service"], sms1["region"], signatureDateTime); err != nil {
		return nil, errors.Wrap(err, "failed to sign temporary HTTP request")
	}

	sms2 := c.reg.getSubmatches(otherRequest.Header.Get("Authorization"))
	if sms1["v4_signature"] != sms2["v4_signature"] {
		return nil, errors.New("failed to pass authentication procedure")
	}

	return tkn, nil
}

// for debug reasons
// func panicSeeker() io.ReadSeeker { return prs(0) }

// TODO: Make this write into a smart buffer backed by a file on a fast drive.
// func readAndKeepBody(request *http.Request) (*bytes.Reader, error) {
// 	if request.Body == nil {
// 		return new(bytes.Reader), nil
// 	}
//
// 	payload, err := ioutil.ReadAll(request.Body)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	request.Body = ioutil.NopCloser(bytes.NewReader(payload))
// 	return bytes.NewReader(payload), nil
// }
