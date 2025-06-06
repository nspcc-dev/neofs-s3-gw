package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	v4amz "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	v4 "github.com/nspcc-dev/neofs-s3-gw/api/auth/signer/v4"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-s3-gw/internal/limits"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// authorizationFieldRegexp -- is regexp for credentials with Base58 encoded cid and oid and '0' (zero) as delimiter.
var authorizationFieldRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256 Credential=(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request,\s*SignedHeaders=(?P<signed_header_fields>.+),\s*Signature=(?P<v4_signature>.+)`)

// postPolicyCredentialRegexp -- is regexp for credentials when uploading file using POST with policy.
var postPolicyCredentialRegexp = regexp.MustCompile(`(?P<access_key_id>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]*)/(?P<service>[^/]+)/aws4_request`)

type (
	// Center is a user authentication interface.
	Center interface {
		Authenticate(request *http.Request) (*Box, error)
	}

	// Box contains access box and additional info.
	Box struct {
		AccessBox  *accessbox.Box
		ClientTime time.Time
	}

	center struct {
		reg                        *RegexpSubmatcher
		postReg                    *RegexpSubmatcher
		cli                        tokens.Credentials
		allowedAccessKeyIDPrefixes []string // empty slice means all access key ids are allowed
	}

	prs int

	authHeader struct {
		AccessKeyID  string
		Service      string
		Region       string
		SignatureV4  string
		SignedFields []string
		Date         string
		IsPresigned  bool
		Expiration   time.Duration
		PayloadHash  string
	}
)

const (
	accessKeyPartsNum  = 2
	authHeaderPartsNum = 6
	maxFormSizeMemory  = 50 * 1048576 // 50 MB

	AmzAlgorithm                  = "X-Amz-Algorithm"
	AmzCredential                 = "X-Amz-Credential"
	AmzSignature                  = "X-Amz-Signature"
	AmzSignedHeaders              = "X-Amz-SignedHeaders"
	AmzExpires                    = "X-Amz-Expires"
	AmzDate                       = "X-Amz-Date"
	AmzContentSha256              = "X-Amz-Content-Sha256"
	AuthorizationHdr              = "Authorization"
	AmzTrailer                    = "x-amz-trailer"
	ContentTypeHdr                = "Content-Type"
	ContentEncodingChunked        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	UnsignedPayloadMultipleChunks = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

	timeFormatISO8601 = "20060102T150405Z"

	// emptyStringSHA256 is a SHA256 of an empty string.
	emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
	UnsignedPayload   = "UNSIGNED-PAYLOAD"
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
func New(neoFS tokens.NeoFS, key *keys.PrivateKey, prefixes []string, config *cache.Config) Center {
	return &center{
		cli:                        tokens.New(neoFS, key, config),
		reg:                        NewRegexpMatcher(authorizationFieldRegexp),
		postReg:                    NewRegexpMatcher(postPolicyCredentialRegexp),
		allowedAccessKeyIDPrefixes: prefixes,
	}
}

func (c *center) parseAuthHeader(header, amzContentSha256Header string) (*authHeader, error) {
	submatches := c.reg.GetSubmatches(header)
	if len(submatches) != authHeaderPartsNum {
		return nil, s3errors.GetAPIError(s3errors.ErrCredMalformed)
	}

	accessKey := strings.Split(submatches["access_key_id"], "0")
	if len(accessKey) != accessKeyPartsNum {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
	}

	signedFields := strings.Split(submatches["signed_header_fields"], ";")

	return &authHeader{
		AccessKeyID:  submatches["access_key_id"],
		Service:      submatches["service"],
		Region:       submatches["region"],
		SignatureV4:  submatches["v4_signature"],
		SignedFields: signedFields,
		Date:         submatches["date"],
		PayloadHash:  amzContentSha256Header,
	}, nil
}

func (a *authHeader) getAddress() (oid.Address, error) {
	addr, err := oid.DecodeAddressString(strings.ReplaceAll(a.AccessKeyID, "0", "/"))
	if err != nil {
		return addr, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
	}
	return addr, nil
}

func (c *center) Authenticate(r *http.Request) (*Box, error) {
	var (
		err                  error
		authHdr              *authHeader
		signatureDateTimeStr string
		needClientTime       bool
	)

	queryValues := r.URL.Query()
	if queryValues.Get(AmzAlgorithm) == "AWS4-HMAC-SHA256" {
		creds := strings.Split(queryValues.Get(AmzCredential), "/")
		if len(creds) != 5 || creds[4] != "aws4_request" {
			return nil, s3errors.GetAPIError(s3errors.ErrCredMalformed)
		}
		authHdr = &authHeader{
			AccessKeyID:  creds[0],
			Service:      creds[3],
			Region:       creds[2],
			SignatureV4:  queryValues.Get(AmzSignature),
			SignedFields: queryValues[AmzSignedHeaders],
			Date:         creds[1],
			IsPresigned:  true,
			PayloadHash:  r.Header.Get(AmzContentSha256),
		}

		if authHdr.PayloadHash == "" {
			authHdr.PayloadHash = UnsignedPayload
		}
		authHdr.Expiration, err = time.ParseDuration(queryValues.Get(AmzExpires) + "s")
		if err != nil {
			return nil, fmt.Errorf("couldn't parse X-Amz-Expires: %w", err)
		}

		if authHdr.Expiration > limits.MaxPreSignedLifetime {
			return nil, s3errors.GetAPIError(s3errors.ErrMaximumExpires)
		}

		signatureDateTimeStr = queryValues.Get(AmzDate)
	} else {
		authHeaderField := r.Header[AuthorizationHdr]
		if len(authHeaderField) != 1 {
			if strings.HasPrefix(r.Header.Get(ContentTypeHdr), "multipart/form-data") {
				return c.checkFormData(r)
			}

			if r.Header.Get(AmzContentSha256) == UnsignedPayloadMultipleChunks {
				r.Body, err = v4.NewChunkedReaderWithTrail(r.Body, r.Header.Get(AmzTrailer))
				if err != nil {
					return nil, err
				}
			}

			return nil, ErrNoAuthorizationHeader
		}
		authHdr, err = c.parseAuthHeader(authHeaderField[0], r.Header.Get(AmzContentSha256))
		if err != nil {
			return nil, err
		}
		signatureDateTimeStr = r.Header.Get(AmzDate)
		needClientTime = true
	}

	signatureDateTime, err := time.Parse(timeFormatISO8601, signatureDateTimeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x-amz-date header field: %w", err)
	}

	if err := c.checkAccessKeyID(authHdr.AccessKeyID); err != nil {
		return nil, err
	}

	addr, err := authHdr.getAddress()
	if err != nil {
		return nil, err
	}

	box, err := c.cli.GetBox(r.Context(), addr)
	if err != nil {
		return nil, fmt.Errorf("get box: %w", err)
	}

	clonedRequest := cloneRequest(r, authHdr)
	if err = c.checkSign(authHdr, box, clonedRequest, signatureDateTime); err != nil {
		return nil, err
	}

	amzContent := r.Header.Get(AmzContentSha256)

	switch amzContent {
	case ContentEncodingChunked:
		sig, err := hex.DecodeString(authHdr.SignatureV4)
		if err != nil {
			return nil, fmt.Errorf("decode auth header signature: %w", err)
		}

		appCreds := credentials.NewStaticCredentialsProvider(authHdr.AccessKeyID, box.Gate.AccessKey, "")
		value, err := appCreds.Retrieve(r.Context())
		if err != nil {
			return nil, fmt.Errorf("retrieve aws credentials: %w", err)
		}

		chunkSigner := v4.NewChunkSigner(authHdr.Region, authHdr.Service, sig, signatureDateTime, value)
		r.Body = v4.NewChunkedReader(r.Body, chunkSigner)
	case UnsignedPayloadMultipleChunks:
		r.Body, err = v4.NewChunkedReaderWithTrail(r.Body, clonedRequest.Header.Get(AmzTrailer))
		if err != nil {
			return nil, err
		}
	}

	result := &Box{AccessBox: box}
	if needClientTime {
		result.ClientTime = signatureDateTime
	}

	return result, nil
}

func (c center) checkAccessKeyID(accessKeyID string) error {
	if len(c.allowedAccessKeyIDPrefixes) == 0 {
		return nil
	}

	for _, prefix := range c.allowedAccessKeyIDPrefixes {
		if strings.HasPrefix(accessKeyID, prefix) {
			return nil
		}
	}

	return s3errors.GetAPIError(s3errors.ErrAccessDenied)
}

func (c *center) checkFormData(r *http.Request) (*Box, error) {
	if err := r.ParseMultipartForm(maxFormSizeMemory); err != nil {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidArgument)
	}

	if err := prepareForm(r.MultipartForm); err != nil {
		return nil, fmt.Errorf("couldn't parse form: %w", err)
	}

	policy := MultipartFormValue(r, "policy")
	if policy == "" {
		return nil, ErrNoAuthorizationHeader
	}

	submatches := c.postReg.GetSubmatches(MultipartFormValue(r, strings.ToLower(AmzCredential)))
	if len(submatches) != 4 {
		return nil, s3errors.GetAPIError(s3errors.ErrCredMalformed)
	}

	signatureDateTime, err := time.Parse("20060102T150405Z", MultipartFormValue(r, "x-amz-date"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse x-amz-date field: %w", err)
	}

	addr, err := oid.DecodeAddressString(strings.ReplaceAll(submatches["access_key_id"], "0", "/"))
	if err != nil {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)
	}

	box, err := c.cli.GetBox(r.Context(), addr)
	if err != nil {
		return nil, fmt.Errorf("get box: %w", err)
	}

	secret := box.Gate.AccessKey
	service, region := submatches["service"], submatches["region"]

	signature := signStr(secret, service, region, signatureDateTime, policy)
	if signature != MultipartFormValue(r, "x-amz-signature") {
		return nil, s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch)
	}

	return &Box{AccessBox: box}, nil
}

func cloneRequest(r *http.Request, authHeader *authHeader) *http.Request {
	otherRequest := r.Clone(r.Context())
	otherRequest.Header = make(http.Header)

	for key, val := range r.Header {
		for _, name := range authHeader.SignedFields {
			if strings.EqualFold(key, name) {
				otherRequest.Header[key] = val
			}
		}
	}

	if authHeader.IsPresigned {
		otherQuery := otherRequest.URL.Query()
		otherQuery.Del(AmzSignature)
		otherRequest.URL.RawQuery = otherQuery.Encode()
	}

	return otherRequest
}

func (c *center) checkSign(authHeader *authHeader, box *accessbox.Box, request *http.Request, signatureDateTime time.Time) error {
	credProvider := credentials.NewStaticCredentialsProvider(authHeader.AccessKeyID, box.Gate.AccessKey, "")
	awsCreds, err := credProvider.Retrieve(request.Context())
	if err != nil {
		return fmt.Errorf("get credentials: %w", err)
	}

	signer := v4amz.NewSigner(func(signer *v4amz.SignerOptions) {
		signer.DisableURIPathEscaping = true
	})

	if authHeader.PayloadHash == "" {
		authHeader.PayloadHash = emptyStringSHA256
	}

	var hasContentLength bool
	for _, h := range authHeader.SignedFields {
		if strings.ToLower(h) == "content-length" {
			hasContentLength = true
			break
		}
	}

	// Final content length is unknown, request.ContentLength == -1.
	if !hasContentLength {
		request.ContentLength = 0
	}

	var signature string
	if authHeader.IsPresigned {
		var (
			now       = time.Now()
			signedURI string
		)
		if signatureDateTime.Add(authHeader.Expiration).Before(now) {
			return s3errors.GetAPIError(s3errors.ErrExpiredPresignRequest)
		}
		if now.Before(signatureDateTime) {
			return s3errors.GetAPIError(s3errors.ErrBadRequest)
		}

		signedURI, _, err = signer.PresignHTTP(request.Context(), awsCreds, request, authHeader.PayloadHash, authHeader.Service, authHeader.Region, signatureDateTime)
		if err != nil {
			return fmt.Errorf("failed to pre-sign temporary HTTP request: %w", err)
		}

		u, err := url.ParseRequestURI(signedURI)
		if err != nil {
			return fmt.Errorf("parse signed uri: %w", err)
		}
		signature = u.Query().Get(AmzSignature)
	} else {
		if err = signer.SignHTTP(request.Context(), awsCreds, request, authHeader.PayloadHash, authHeader.Service, authHeader.Region, signatureDateTime); err != nil {
			return fmt.Errorf("failed to sign temporary HTTP request: %w", err)
		}
		signature = c.reg.GetSubmatches(request.Header.Get(AuthorizationHdr))["v4_signature"]
	}

	if authHeader.SignatureV4 != signature {
		return s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch)
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
					return fmt.Errorf("file header open: %w", err)
				}

				data, err := io.ReadAll(field)
				if err != nil {
					return fmt.Errorf("read field: %w", err)
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
