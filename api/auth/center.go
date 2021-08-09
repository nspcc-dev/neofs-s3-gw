package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"go.uber.org/zap"
)

// authorizationFieldRegexp -- is regexp for credentials with Base58 encoded cid and oid and '0' (zero) as delimiter.
var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id_cid>[^/]+)0(?P<access_key_id_oid>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

type (
	// Center is a user authentication interface.
	Center interface {
		Authenticate(request *http.Request) (*accessbox.Box, error)
	}

	center struct {
		reg *regexpSubmatcher
		cli tokens.Credentials
	}

	// Params stores node connection parameters.
	Params struct {
		Pool   pool.Pool
		Logger *zap.Logger
	}

	prs int
)

// ErrNoAuthorizationHeader is returned for unauthenticated requests.
var ErrNoAuthorizationHeader = errors.New("no authorization header")

func (p prs) Read(_ []byte) (n int, err error) {
	panic("implement me")
}

func (p prs) Seek(_ int64, _ int) (int64, error) {
	panic("implement me")
}

var _ io.ReadSeeker = prs(0)

// New creates an instance of AuthCenter.
func New(conns pool.Pool, key *keys.PrivateKey) Center {
	return &center{
		cli: tokens.New(conns, key),
		reg: &regexpSubmatcher{re: authorizationFieldRegexp},
	}
}

func (c *center) Authenticate(r *http.Request) (*accessbox.Box, error) {
	queryValues := r.URL.Query()
	if queryValues.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return nil, errors.New("pre-signed form of request is not supported")
	}

	authHeaderField := r.Header["Authorization"]
	if len(authHeaderField) != 1 {
		return nil, ErrNoAuthorizationHeader
	}

	sms1 := c.reg.getSubmatches(authHeaderField[0])
	if len(sms1) != 7 {
		return nil, apiErrors.GetAPIError(apiErrors.ErrAuthorizationHeaderMalformed)
	}

	signedHeaderFieldsNames := strings.Split(sms1["signed_header_fields"], ";")
	if len(signedHeaderFieldsNames) == 0 {
		return nil, errors.New("wrong format of signed headers part")
	}

	signatureDateTime, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse x-amz-date header field: %w", err)
	}

	accessKeyID := fmt.Sprintf("%s0%s", sms1["access_key_id_cid"], sms1["access_key_id_oid"])
	accessKeyAddress := fmt.Sprintf("%s/%s", sms1["access_key_id_cid"], sms1["access_key_id_oid"])

	address := object.NewAddress()
	if err = address.Parse(accessKeyAddress); err != nil {
		return nil, fmt.Errorf("could not parse AccessBox address: %s : %w", accessKeyID, err)
	}

	box, err := c.cli.GetBox(r.Context(), address)
	if err != nil {
		return nil, err
	}

	otherRequest := r.Clone(context.TODO())
	otherRequest.Header = make(http.Header)

	for key, val := range r.Header {
		for _, name := range signedHeaderFieldsNames {
			if strings.EqualFold(key, name) {
				otherRequest.Header[key] = val
			}
		}
	}

	awsCreds := credentials.NewStaticCredentials(accessKeyID, box.Gate.AccessKey, "")
	signer := v4.NewSigner(awsCreds)
	signer.DisableURIPathEscaping = true

	// body not required
	if _, err := signer.Sign(otherRequest, nil, sms1["service"], sms1["region"], signatureDateTime); err != nil {
		return nil, fmt.Errorf("failed to sign temporary HTTP request: %w", err)
	}

	sms2 := c.reg.getSubmatches(otherRequest.Header.Get("Authorization"))
	if sms1["v4_signature"] != sms2["v4_signature"] {
		return nil, apiErrors.GetAPIError(apiErrors.ErrSignatureDoesNotMatch)
	}

	return box, nil
}
