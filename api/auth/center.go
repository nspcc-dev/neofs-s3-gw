package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	apiErrors "github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// authorizationFieldRegexp -- is regexp for credentials with Base58 encoded cid and oid and '0' (zero) as delimiter.
var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

// postPolicyCredentialRegexp -- is regexp for credentials when uploading file using POST with policy.
var postPolicyCredentialRegexp = regexp.MustCompile(`(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request`)

type (
	// Center is a user authentication interface.
	Center interface {
		Authenticate(request *http.Request) (*accessbox.Box, error)
	}

	center struct {
		reg     *regexpSubmatcher
		postReg *regexpSubmatcher
		cli     tokens.Credentials
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
	maxFormSizeMemory  = 50 * 1048576 // 50 MB
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
func New(neoFS tokens.NeoFS, key *keys.PrivateKey, config *cache.Config) Center {
	return &center{
		cli:     tokens.New(neoFS, key, config),
		reg:     &regexpSubmatcher{re: authorizationFieldRegexp},
		postReg: &regexpSubmatcher{re: postPolicyCredentialRegexp},
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

func (a *authHeader) getAddress() (*oid.Address, error) {
	var addr oid.Address
	if err := addr.DecodeString(strings.ReplaceAll(a.AccessKeyID, "0", "/")); err != nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrInvalidAccessKeyID)
	}
	return &addr, nil
}

func (c *center) Authenticate(r *http.Request) (*accessbox.Box, error) {
	queryValues := r.URL.Query()
	if queryValues.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return nil, errors.New("pre-signed form of request is not supported")
	}

	authHeaderField := r.Header["Authorization"]
	if len(authHeaderField) != 1 {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			return c.checkFormData(r)
		}
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

	addr, err := authHeader.getAddress()
	if err != nil {
		return nil, err
	}

	box, err := c.cli.GetBox(r.Context(), *addr)
	if err != nil {
		return nil, err
	}

	clonedRequest := cloneRequest(r, authHeader)
	if err = c.checkSign(authHeader, box, clonedRequest, signatureDateTime); err != nil {
		return nil, err
	}

	return box, nil
}

func (c *center) checkFormData(r *http.Request) (*accessbox.Box, error) {
	if err := r.ParseMultipartForm(maxFormSizeMemory); err != nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrInvalidArgument)
	}

	if err := prepareForm(r.MultipartForm); err != nil {
		return nil, fmt.Errorf("couldn't parse form: %w", err)
	}

	policy := MultipartFormValue(r, "policy")
	if policy == "" {
		return nil, ErrNoAuthorizationHeader
	}

	submatches := c.postReg.getSubmatches(MultipartFormValue(r, "x-amz-credential"))
	if len(submatches) != 4 {
		return nil, apiErrors.GetAPIError(apiErrors.ErrAuthorizationHeaderMalformed)
	}

	signatureDateTime, err := time.Parse("20060102T150405Z", MultipartFormValue(r, "x-amz-date"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse x-amz-date field: %w", err)
	}

	var addr oid.Address
	if err = addr.DecodeString(strings.ReplaceAll(submatches["access_key_id"], "0", "/")); err != nil {
		return nil, apiErrors.GetAPIError(apiErrors.ErrInvalidAccessKeyID)
	}

	box, err := c.cli.GetBox(r.Context(), addr)
	if err != nil {
		return nil, err
	}

	secret := box.Gate.AccessKey
	service, region := submatches["service"], submatches["region"]

	signature := signStr(secret, service, region, signatureDateTime, policy)
	if signature != MultipartFormValue(r, "x-amz-signature") {
		return nil, apiErrors.GetAPIError(apiErrors.ErrSignatureDoesNotMatch)
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

func signStr(secret, service, region string, t time.Time, strToSign string) string {
	creds := deriveKey(secret, service, region, t)
	signature := hmacSHA256(creds, []byte(strToSign))
	return hex.EncodeToString(signature)
}

func deriveKey(secret, service, region string, t time.Time) []byte {
	hmacDate := hmacSHA256([]byte("AWS4"+secret), []byte(t.UTC().Format("20060102")))
	hmacRegion := hmacSHA256(hmacDate, []byte(region))
	hmacService := hmacSHA256(hmacRegion, []byte(service))
	return hmacSHA256(hmacService, []byte("aws4_request"))
}

func hmacSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// MultipartFormValue gets value by key from multipart form.
func MultipartFormValue(r *http.Request, key string) string {
	if r.MultipartForm == nil {
		return ""
	}
	if vs := r.MultipartForm.Value[key]; len(vs) > 0 {
		return vs[0]
	}

	return ""
}

func prepareForm(form *multipart.Form) error {
	var oldKeysValue []string
	var oldKeysFile []string

	for k, v := range form.Value {
		lowerKey := strings.ToLower(k)
		if lowerKey != k {
			form.Value[lowerKey] = v
			oldKeysValue = append(oldKeysValue, k)
		}
	}
	for _, k := range oldKeysValue {
		delete(form.Value, k)
	}

	for k, v := range form.File {
		lowerKey := strings.ToLower(k)
		if lowerKey != "file" {
			oldKeysFile = append(oldKeysFile, k)
			if len(v) > 0 {
				field, err := v[0].Open()
				if err != nil {
					return err
				}

				data, err := io.ReadAll(field)
				if err != nil {
					return err
				}
				form.Value[lowerKey] = []string{string(data)}
			}
		} else if lowerKey != k {
			form.File[lowerKey] = v
			oldKeysFile = append(oldKeysFile, k)
		}
	}
	for _, k := range oldKeysFile {
		delete(form.File, k)
	}

	return nil
}
