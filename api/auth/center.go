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
var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

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

	authHeader struct {
		AccessKeyID  string
		Service      string
		Region       string
		SignatureV4  string
		SignedFields []string
		Date         string
	}
)

const (
	accessKeyPartsNum  = 2
	authHeaderPartsNum = 6
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

func (c *center) parseAuthHeader(header string) (*authHeader, error) {
	submatches := c.reg.getSubmatches(header)
	if len(submatches) != authHeaderPartsNum {
		return nil, apiErrors.GetAPIError(apiErrors.ErrAuthorizationHeaderMalformed)
	}

	accessKey := strings.Split(submatches["access_key_id"], "0")
	if len(accessKey) != accessKeyPartsNum {
		return nil, apiErrors.GetAPIError(apiErrors.ErrInvalidAccessKeyID)
	}

	signedFields := strings.Split(submatches["signed_header_fields"], ";")

	return &authHeader{
		AccessKeyID:  submatches["access_key_id"],
		Service:      submatches["service"],
		Region:       submatches["region"],
		SignatureV4:  submatches["v4_signature"],
		SignedFields: signedFields,
		Date:         submatches["date"],
	}, nil
}

func (a *authHeader) getAddress() (*object.Address, error) {
	address := object.NewAddress()
	if err := address.Parse(strings.ReplaceAll(a.AccessKeyID, "0", "/")); err != nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrInvalidAccessKeyID)
	}
	return address, nil
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

	authHeader, err := c.parseAuthHeader(authHeaderField[0])
	if err != nil {
		return nil, err
	}

	signatureDateTime, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse x-amz-date header field: %w", err)
	}

	address, err := authHeader.getAddress()
	if err != nil {
		return nil, err
	}

	box, err := c.cli.GetBox(r.Context(), address)
	if err != nil {
		return nil, err
	}

	clonedRequest := cloneRequest(r, authHeader)
	if err = c.checkSign(authHeader, box, clonedRequest, signatureDateTime); err != nil {
		return nil, err
	}

	return box, nil
}

func cloneRequest(r *http.Request, authHeader *authHeader) *http.Request {
	otherRequest := r.Clone(context.TODO())
	otherRequest.Header = make(http.Header)

	for key, val := range r.Header {
		for _, name := range authHeader.SignedFields {
			if strings.EqualFold(key, name) {
				otherRequest.Header[key] = val
			}
		}
	}

	return otherRequest
}

func (c *center) checkSign(authHeader *authHeader, box *accessbox.Box, request *http.Request, signatureDateTime time.Time) error {
	awsCreds := credentials.NewStaticCredentials(authHeader.AccessKeyID, box.Gate.AccessKey, "")
	signer := v4.NewSigner(awsCreds)
	signer.DisableURIPathEscaping = true

	// body not required
	if _, err := signer.Sign(request, nil, authHeader.Service, authHeader.Region, signatureDateTime); err != nil {
		return fmt.Errorf("failed to sign temporary HTTP request: %w", err)
	}

	sms2 := c.reg.getSubmatches(request.Header.Get("Authorization"))
	if authHeader.SignatureV4 != sms2["v4_signature"] {
		return apiErrors.GetAPIError(apiErrors.ErrSignatureDoesNotMatch)
	}

	return nil
}
