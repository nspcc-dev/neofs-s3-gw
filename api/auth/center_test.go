package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	v4amz "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	v4 "github.com/nspcc-dev/neofs-s3-gw/api/auth/signer/v4"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
)

func TestAuthHeaderParse(t *testing.T) {
	defaultHeader := "AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2811ccb9e242f41426738fb1f"

	center := &center{}

	for _, tc := range []struct {
		header   string
		err      error
		expected *authHeader
	}{
		{
			header: defaultHeader,
			err:    nil,
			expected: &authHeader{
				AccessKeyID:  "oid0cid",
				Service:      "s3",
				Region:       "us-east-1",
				SignatureV4:  "2811ccb9e242f41426738fb1f",
				SignedFields: []string{"host", "x-amz-content-sha256", "x-amz-date"},
				Date:         "20210809",
			},
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "Signature=2811ccb9e242f41426738fb1f", ""),
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "oid0cid", "oidcid"),
			err:      s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID),
			expected: nil,
		},
		{
			header: strings.ReplaceAll(defaultHeader, ", ", ","),
			err:    nil,
			expected: &authHeader{
				AccessKeyID:  "oid0cid",
				Service:      "s3",
				Region:       "us-east-1",
				SignatureV4:  "2811ccb9e242f41426738fb1f",
				SignedFields: []string{"host", "x-amz-content-sha256", "x-amz-date"},
				Date:         "20210809",
			},
		},
		{
			header: strings.ReplaceAll(defaultHeader, "us-east-1", ""),
			err:    nil,
			expected: &authHeader{
				AccessKeyID:  "oid0cid",
				Service:      "s3",
				Region:       "",
				SignatureV4:  "2811ccb9e242f41426738fb1f",
				SignedFields: []string{"host", "x-amz-content-sha256", "x-amz-date"},
				Date:         "20210809",
			},
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "aws4_request", "aws4"),
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "SignedHeaders=host;x-amz-content-sha256;x-amz-date, ", ""),
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
		{
			header: "aws4-hmac-sha256 signature=2811ccb9e242f41426738fb1f, credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=\"host;x-amz-content-sha256;x-amz-date\"",
			err:    nil,
			expected: &authHeader{
				AccessKeyID:  "oid0cid",
				Service:      "s3",
				Region:       "us-east-1",
				SignatureV4:  "2811ccb9e242f41426738fb1f",
				SignedFields: []string{"host", "x-amz-content-sha256", "x-amz-date"},
				Date:         "20210809",
			},
		},
		{
			header:   defaultHeader + ", Signature=2811ccb9e242f41426738fb1f",
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "Signature=", "Signature=abc "),
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "/s3/", "/s3/extra/"),
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
		{
			header:   "Bearer token",
			err:      s3errors.GetAPIError(s3errors.ErrCredMalformed),
			expected: nil,
		},
	} {
		authHeader, err := center.parseAuthHeader(tc.header, "")
		require.Equal(t, tc.err, err, tc.header)
		require.Equal(t, tc.expected, authHeader, tc.header)
	}
}

func TestAuthHeaderGetAddress(t *testing.T) {
	defaulErr := s3errors.GetAPIError(s3errors.ErrInvalidAccessKeyID)

	for _, tc := range []struct {
		authHeader *authHeader
		err        error
	}{
		{
			authHeader: &authHeader{
				AccessKeyID: "vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJM0HrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB",
			},
			err: nil,
		},
		{
			authHeader: &authHeader{
				AccessKeyID: "vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJMHrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB",
			},
			err: defaulErr,
		},
		{
			authHeader: &authHeader{
				AccessKeyID: "oid0cid",
			},
			err: defaulErr,
		},
		{
			authHeader: &authHeader{
				AccessKeyID: "oidcid",
			},
			err: defaulErr,
		},
	} {
		_, err := tc.authHeader.getAddress()
		require.Equal(t, tc.err, err, tc.authHeader.AccessKeyID)
	}
}

func TestSignature(t *testing.T) {
	secret := "66be461c3cd429941c55daf42fad2b8153e5a2016ba89c9494d97677cc9d3872"
	strToSign := "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLAogICJjb25kaXRpb25zIjogWwogICAgeyJidWNrZXQiOiAiYWNsIn0sCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwKICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL2xvY2FsaG9zdDo4MDg0L2FjbCJ9LAogICAgWyJzdGFydHMtd2l0aCIsICIkQ29udGVudC1UeXBlIiwgImltYWdlLyJdLAogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwKICAgIFsic3RhcnRzLXdpdGgiLCAiJHgtYW16LW1ldGEtdGFnIiwgIiJdLAoKICAgIHsiWC1BbXotQ3JlZGVudGlhbCI6ICI4Vmk0MVBIbjVGMXNzY2J4OUhqMXdmMUU2aERUYURpNndxOGhxTU05NllKdTA1QzVDeUVkVlFoV1E2aVZGekFpTkxXaTlFc3BiUTE5ZDRuR3pTYnZVZm10TS8yMDE1MTIyOS91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0sCiAgICB7IngtYW16LWFsZ29yaXRobSI6ICJBV1M0LUhNQUMtU0hBMjU2In0sCiAgICB7IlgtQW16LURhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfSwKICAgIHsieC1pZ25vcmUtdG1wIjogInNvbWV0aGluZyIgfQogIF0KfQ=="

	signTime, err := time.Parse("20060102T150405Z", "20151229T000000Z")
	if err != nil {
		panic(err)
	}

	signature := signStr(secret, "s3", "us-east-1", signTime, strToSign)
	require.Equal(t, "dfbe886241d9e369cf4b329ca0f15eb27306c97aa1022cc0bb5a914c4ef87634", signature)
}

// Requests as sent by MinIO Java SDK 9.0.4: with no body it signs "content-length:0".
func TestCheckSignZeroContentLength(t *testing.T) {
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	box := &accessbox.Box{Gate: &accessbox.GateData{AccessKey: "secretsecret"}}

	for _, tc := range []struct {
		name, method, target, date, signedHeaders, signature string
		headers                                              map[string]string
	}{
		{
			name:          "CreateMultipartUpload",
			method:        http.MethodPost,
			target:        "/bkt/k?uploads=",
			date:          "20261116T052623Z",
			signedHeaders: "content-length;content-md5;content-type;host;x-amz-checksum-algorithm;x-amz-content-sha256;x-amz-date",
			signature:     "b5291fd5ac2a002dd490742271992f3bf3a9a54cf1cefe8554797c71071fa034",
			headers:       map[string]string{"X-Amz-Checksum-Algorithm": "crc32c"},
		},
		{
			name:          "CopyObject",
			method:        http.MethodPut,
			target:        "/bkt/dst",
			date:          "20261116T052621Z",
			signedHeaders: "content-length;content-md5;content-type;host;x-amz-content-sha256;x-amz-copy-source;x-amz-copy-source-if-match;x-amz-date",
			signature:     "8bb8cf009b120167e03ba277cc42aed94aad2aa354949c05558e51d2e3304747",
			headers:       map[string]string{"X-Amz-Copy-Source": "/bkt/src", "X-Amz-Copy-Source-If-Match": "abc"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signTime, err := time.Parse(timeFormatISO8601, tc.date)
			require.NoError(t, err)

			newRequest := func() (*http.Request, *authHeader) {
				r := httptest.NewRequest(tc.method, "http://127.0.0.1:19555"+tc.target, http.NoBody)
				r.Header.Set("X-Amz-Date", tc.date)
				r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
				r.Header.Set("Content-Md5", "1B2M2Y8AsgTpgAmY7PhCfg==")
				r.Header.Set("Content-Type", "application/octet-stream")
				r.Header.Set("Content-Length", "0")
				r.Header.Set("User-Agent", "MinIO (Linux; amd64) minio-java/9.0.4")
				r.Header.Set("Accept-Encoding", "identity")
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				return r, &authHeader{
					AccessKeyID:  "AKIDEXAMPLE",
					Service:      "s3",
					Region:       "us-east-1",
					SignatureV4:  tc.signature,
					SignedFields: strings.Split(tc.signedHeaders, ";"),
					Date:         tc.date[:8],
					PayloadHash:  emptySHA256,
				}
			}
			c := &center{}

			r, hdr := newRequest()
			require.NoError(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime))

			r, hdr = newRequest()
			r.Header.Set("Content-Md5", "AAAAAAAAAAAAAAAAAAAAAA==")
			require.ErrorIs(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime), s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))

			r, hdr = newRequest()
			r.URL.Path += "x"
			require.ErrorIs(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime), s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))
		})
	}
}

func TestCheckFormDataNoSignature(t *testing.T) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	require.NoError(t, form.WriteField("key", "foo.txt"))
	require.NoError(t, form.WriteField("policy", "e30="))
	require.NoError(t, form.WriteField("x-amz-credential", "key/20151229/us-east-1/s3/aws4_request"))
	require.NoError(t, form.WriteField("x-amz-date", "20151229T000000Z"))
	require.NoError(t, form.Close())

	r, err := http.NewRequest(http.MethodPost, "/bucket", &body)
	require.NoError(t, err)
	r.Header.Set(ContentTypeHdr, form.FormDataContentType())

	c := &center{postReg: NewRegexpMatcher(postPolicyCredentialRegexp)}
	_, err = c.checkFormData(r)
	require.ErrorIs(t, err, s3errors.GetAPIError(s3errors.ErrInvalidArgument))
}

// TestAwsEncodedChunkReaderSignedTrailer checks the example from
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html
func TestAwsEncodedChunkReaderSignedTrailer(t *testing.T) {
	const (
		seed      = "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e"
		chunkOne  = "10000;chunk-signature=b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2\r\n"
		chunkTwo  = "400;chunk-signature=1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7\r\n"
		chunkLast = "0;chunk-signature=2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992\r\n"
		checksum  = "x-amz-checksum-crc32c:sOO8/Q==\r\n"
		trailer   = "x-amz-trailer-signature:d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435\r\n"
	)

	payload := bytes.Repeat([]byte{'a'}, 65536+1024)
	appCreds := credentials.NewStaticCredentialsProvider("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "")
	awsCreds, err := appCreds.Retrieve(context.Background())
	require.NoError(t, err)

	ts, err := time.Parse(timeFormatISO8601, "20130524T000000Z")
	require.NoError(t, err)

	seedSignature, err := hex.DecodeString(seed)
	require.NoError(t, err)

	body := func(parts ...string) io.ReadCloser {
		buf := bytes.NewBuffer(nil)
		for _, p := range parts {
			switch p {
			case chunkOne:
				buf.WriteString(p)
				buf.Write(payload[:65536])
				buf.WriteString("\r\n")
			case chunkTwo:
				buf.WriteString(p)
				buf.Write(payload[65536:])
				buf.WriteString("\r\n")
			default:
				buf.WriteString(p)
			}
		}
		buf.WriteString("\r\n")
		return io.NopCloser(buf)
	}

	read := func(t *testing.T, r io.ReadCloser, trailerHeader string) ([]byte, error) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkedReader, err := v4.NewChunkedReaderWithSignedTrail(r, streamSigner, trailerHeader)
		require.NoError(t, err)
		got := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(got, chunkedReader, make([]byte, 4096))
		return got.Bytes(), err
	}

	t.Run("correct signatures", func(t *testing.T) {
		got, err := read(t, body(chunkOne, chunkTwo, chunkLast, checksum, trailer), "x-amz-checksum-crc32c")
		require.NoError(t, err)
		require.Equal(t, payload, got)
	})

	t.Run("invalid trailer signature", func(t *testing.T) {
		bad := "x-amz-trailer-signature:" + strings.Repeat("0", 64) + "\r\n"
		_, err := read(t, body(chunkOne, chunkTwo, chunkLast, checksum, bad), "x-amz-checksum-crc32c")
		require.ErrorIs(t, err, v4.ErrInvalidTrailerSignature)
	})

	t.Run("missing trailer signature", func(t *testing.T) {
		_, err := read(t, body(chunkOne, chunkTwo, chunkLast, checksum), "x-amz-checksum-crc32c")
		require.ErrorIs(t, err, v4.ErrInvalidTrailerSignature)
	})

	t.Run("invalid chunk signature", func(t *testing.T) {
		bad := "400;chunk-signature=" + strings.Repeat("0", 64) + "\r\n"
		buf := bytes.NewBufferString(chunkOne)
		buf.Write(payload[:65536])
		buf.WriteString("\r\n" + bad)
		buf.Write(payload[65536:])
		buf.WriteString("\r\n" + chunkLast + checksum + trailer + "\r\n")
		_, err := read(t, io.NopCloser(buf), "x-amz-checksum-crc32c")
		require.ErrorIs(t, err, v4.ErrInvalidChunkSignature)
	})

	t.Run("chunk without signature", func(t *testing.T) {
		buf := bytes.NewBufferString(chunkOne)
		buf.Write(payload[:65536])
		buf.WriteString("\r\n400\r\n")
		buf.Write(payload[65536:])
		buf.WriteString("\r\n" + chunkLast + checksum + trailer + "\r\n")
		_, err := read(t, io.NopCloser(buf), "x-amz-checksum-crc32c")
		require.ErrorIs(t, err, v4.ErrInvalidChunkSignature)
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		_, err := read(t, body(chunkOne, chunkTwo, chunkLast, "x-amz-checksum-crc32c:AAAAAA==\r\n", trailer), "x-amz-checksum-crc32c")
		require.Error(t, err)
	})

	t.Run("no checksum declared", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		_, err := v4.NewChunkedReaderWithSignedTrail(body(), streamSigner, "")
		require.Error(t, err)
	})
}

// TestAwsEncodedChunkReader checks example from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
func TestAwsEncodedChunkReader(t *testing.T) {
	chunkOnePayload := make([]byte, 65536)
	for i := range 65536 {
		chunkOnePayload[i] = 'a'
	}

	chunkOneBody := append([]byte("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\n"), chunkOnePayload...)
	appCreds := credentials.NewStaticCredentialsProvider("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "")
	awsCreds, err := appCreds.Retrieve(context.Background())
	require.NoError(t, err)

	ts, err := time.Parse(timeFormatISO8601, "20130524T000000Z")
	require.NoError(t, err)

	seedSignature, err := hex.DecodeString("4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
	require.NoError(t, err)

	chunkTwoPayload := make([]byte, 1024)
	for i := range 1024 {
		chunkTwoPayload[i] = 'a'
	}

	chunkTwoBody := append([]byte("400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\n"), chunkTwoPayload...)

	t.Run("correct signature", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.NoError(t, err)

		require.Equal(t, slices.Concat(chunkOnePayload, chunkTwoPayload), payload.Bytes())
	})

	t.Run("err invalid chunk signature", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("0;chunk-signature=000\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.ErrorIs(t, err, v4.ErrInvalidChunkSignature)
	})

	t.Run("err missing separator", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("0chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.ErrorIs(t, err, v4.ErrInvalidByteInChunkLength)
	})

	t.Run("err missing equality byte", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("0;chunk-signatureb6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.Error(t, err)
	})

	t.Run("invalid hex byte", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("h;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.Error(t, err)
	})

	t.Run("invalid hex length", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("11111111111111111;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.Error(t, err)
	})

	t.Run("err missing between chunks separator", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := []byte("0;chunk-signatureb6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\n")

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.ErrorIs(t, err, v4.ErrInvalidChunkSignature)
	})

	t.Run("err chunk header too long", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := make([]byte, 4097)
		for i := range chunkThreeBody {
			chunkThreeBody[i] = 'a'
		}

		chunkThreeBody[4] = ';'
		chunkThreeBody[len(chunkThreeBody)-1] = '\n'

		buf := bytes.NewBuffer(nil)
		chunks := [][]byte{chunkOneBody, chunkTwoBody, chunkThreeBody}

		for _, chunk := range chunks {
			_, err = buf.Write(chunk)
			require.NoError(t, err)
			_, err = buf.Write([]byte{'\r', '\n'})
			require.NoError(t, err)
		}

		chunkedReader := v4.NewChunkedReader(io.NopCloser(buf), streamSigner)
		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload, chunkedReader, chunk)

		require.ErrorIs(t, err, v4.ErrLineTooLong)
	})
}

func TestAwsEncodedWithRequest(t *testing.T) {
	t.Skipf("Only for manual launch")

	ts := time.Now()
	ctx := context.Background()

	host := "http://localhost:19080"
	bucketName := "heh1701422026"
	fileName := strconv.FormatInt(time.Now().Unix(), 16)
	totalPayloadLength := 66560
	chunkSize := 65536

	payload := make([]byte, totalPayloadLength)
	for i := range totalPayloadLength {
		payload[i] = 'a'
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/%s/%s.txt", host, bucketName, fileName), nil)
	require.NoError(t, err)

	tsISO8601 := ts.Format(timeFormatISO8601)

	req.Header.Set("x-amz-date", tsISO8601)
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.Header.Set("content-encoding", "aws-chunked")
	req.Header.Set("x-amz-decoded-content-length", strconv.Itoa(totalPayloadLength))

	appCreds := credentials.NewStaticCredentialsProvider(
		"6cpBf2jzHdD2MJHsjwLuVYYDAPJcfsJ5oufJWnHhrSBQ0FPjWXxmLmvKDAyhr1SEwnfKLJq3twKzuWG7f24qfyWcD", // access_key_id
		"79488f248493cb5175ea079a12a3e08015021d9c710a064017e1da6a2b0ae111",                          // secret_access_key
		"")

	awsCreds, err := appCreds.Retrieve(ctx)
	require.NoError(t, err)

	signer := v4amz.NewSigner(func(signer *v4amz.SignerOptions) {
		signer.DisableURIPathEscaping = true
	})

	h := sha256.New()
	h.Write(payload)

	err = signer.SignHTTP(ctx, awsCreds, req, hex.EncodeToString(h.Sum(nil)), "s3", "us-east-1", ts)
	require.NoError(t, err)

	signature := signatureFromAuthHeader(req.Header.Get(AuthorizationHdr))

	seedSignature, err := hex.DecodeString(signature)
	require.NoError(t, err)

	buff := bytes.NewBuffer(nil)
	chunks := chunkSlice(payload, chunkSize)
	streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)

	for i, chunkPayload := range chunks {
		chunkSignature, err := streamSigner.GetSignature(chunkPayload)
		require.NoError(t, err)

		var body []byte
		if i > 0 {
			body = []byte{'\r', '\n'}
		}

		body = append(body, []byte(strconv.FormatInt(int64(len(chunkPayload)), 16)+";chunk-signature=")...)
		body = append(body, []byte(hex.EncodeToString(chunkSignature))...)
		body = append(body, '\n')
		body = append(body, chunkPayload...)

		_, err = buff.Write(body)
		require.NoError(t, err)
	}

	// the last chunk always has no data and zero length.
	signChunk, err := streamSigner.GetSignature(nil)
	require.NoError(t, err)

	chunk3Body := append([]byte("\r\n0;chunk-signature="), []byte(hex.EncodeToString(signChunk))...)
	chunk3Body = append(chunk3Body, '\n')
	_, err = buff.Write(chunk3Body)
	require.NoError(t, err)

	req.Body = io.NopCloser(buff)
	req.Header.Set("content-length", strconv.Itoa(buff.Len()))

	res, err := http.DefaultClient.Do(req)
	res.Body.Close()
	require.NoError(t, err)
}

func chunkSlice(payload []byte, chunkSize int) [][]byte {
	var result [][]byte

	for i := 0; i < len(payload); i += chunkSize {
		end := min(i+chunkSize, len(payload))

		result = append(result, payload[i:end])
	}

	return result
}

func TestAwsEncodedChunkReaderWithTrailer(t *testing.T) {
	chunk1 := "2000\r\n" + strings.Repeat("a", 8192) + "\r\n"
	chunk2 := "2000\r\n" + strings.Repeat("a", 8192) + "\r\n"
	chunk3 := "400\r\n" + strings.Repeat("a", 1024) + "\r\n"
	chunk4 := "0\r\n"

	var (
		objectPayload = strings.Repeat("a", 17408)
		writer        = crc32.NewIEEE()
		checksumType  = "x-amz-checksum-crc32"
	)

	_, err := writer.Write([]byte(objectPayload))
	require.NoError(t, err)

	var (
		checksum              = writer.Sum(nil)
		base64EncodedChecksum = base64.StdEncoding.EncodeToString(checksum)
		trailer               = checksumType + ":" + base64EncodedChecksum + "\n\r\n\r\n\r\n"
		requestPayload        = chunk1 + chunk2 + chunk3 + chunk4 + trailer
	)

	t.Run("correct signature", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)

		_, err = buf.Write([]byte(requestPayload))
		require.NoError(t, err)

		chunkedReader, err := v4.NewChunkedReaderWithTrail(io.NopCloser(buf), checksumType)
		require.NoError(t, err)

		defer func() {
			_ = chunkedReader.Close()
		}()

		chunk := make([]byte, 4096)
		payload2 := bytes.NewBuffer(nil)
		_, err = io.CopyBuffer(payload2, chunkedReader, chunk)
		require.NoError(t, err)

		require.Equal(t, []byte(objectPayload), payload2.Bytes())
	})
}

func TestSignatureFromAuthHeader(t *testing.T) {
	require.Equal(t, "2811ccb9e242f41426738fb1f", signatureFromAuthHeader("AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=2811ccb9e242f41426738fb1f"))
	require.Equal(t, "", signatureFromAuthHeader("AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=host"))
	require.Equal(t, "2811ccb9e242f41426738fb1f", signatureFromAuthHeader("AWS4-HMAC-SHA256 Signature=2811ccb9e242f41426738fb1f, Credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=host"))
	require.Equal(t, "2811ccb9e242f41426738fb1f", signatureFromAuthHeader(`AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request,SignedHeaders=host, signature = "2811ccb9e242f41426738fb1f" `))
	require.Equal(t, "", signatureFromAuthHeader("AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request, XSignature=2811ccb9e242f41426738fb1f"))
	require.Equal(t, "", signatureFromAuthHeader("Basic Signature=2811ccb9e242f41426738fb1f"))
}

type boxStub struct {
	tokens.Credentials
	box   *accessbox.Box
	calls int
}

var errBoxStub = errors.New("box stub")

func (s *boxStub) GetBox(context.Context, oid.Address) (*accessbox.Box, error) {
	s.calls++
	if s.box == nil {
		return nil, errBoxStub
	}
	return s.box, nil
}

func TestAuthenticateClockSkew(t *testing.T) {
	const accessKeyID = "vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJM0HrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB"

	t.Run("header", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			offset time.Duration
			err    error
		}{
			{name: "now", err: errBoxStub},
			{name: "5 minutes ago", offset: -5 * time.Minute, err: errBoxStub},
			{name: "5 minutes ahead", offset: 5 * time.Minute, err: errBoxStub},
			{name: "30 minutes ago", offset: -30 * time.Minute, err: s3errors.GetAPIError(s3errors.ErrRequestTimeTooSkewed)},
			{name: "30 minutes ahead", offset: 30 * time.Minute, err: s3errors.GetAPIError(s3errors.ErrRequestTimeTooSkewed)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				date := time.Now().Add(tc.offset).UTC()
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set(AmzDate, date.Format(timeFormatISO8601))
				r.Header.Set(AuthorizationHdr, "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/"+date.Format("20060102")+
					"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=00")

				cli := &boxStub{}
				_, err := (&center{cli: cli}).Authenticate(r)
				require.ErrorIs(t, err, tc.err)
				if !errors.Is(tc.err, errBoxStub) {
					require.Zero(t, cli.calls)
				}
			})
		}
	})

	t.Run("presigned", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			offset time.Duration
			err    error
		}{
			{name: "5 minutes ahead", offset: 5 * time.Minute, err: s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch)},
			{name: "30 minutes ahead", offset: 30 * time.Minute, err: s3errors.GetAPIError(s3errors.ErrRequestNotReadyYet)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				date := time.Now().Add(tc.offset).UTC()
				query := url.Values{
					AmzAlgorithm:     {"AWS4-HMAC-SHA256"},
					AmzCredential:    {accessKeyID + "/" + date.Format("20060102") + "/us-east-1/s3/aws4_request"},
					AmzDate:          {date.Format(timeFormatISO8601)},
					AmzExpires:       {"3600"},
					AmzSignedHeaders: {"host"},
					AmzSignature:     {"00"},
				}
				r := httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil)

				cli := &boxStub{box: &accessbox.Box{Gate: &accessbox.GateData{AccessKey: "secret"}}}
				_, err := (&center{cli: cli}).Authenticate(r)
				require.ErrorIs(t, err, tc.err)
			})
		}
	})
}

func TestAuthenticatePresignedParams(t *testing.T) {
	const accessKeyID = "vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJM0HrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB"

	for _, tc := range []struct {
		name    string
		expires []string
		err     error
	}{
		{name: "valid", expires: []string{"3600"}, err: errBoxStub},
		{name: "maximum", expires: []string{"604800"}, err: errBoxStub},
		{name: "missing", err: s3errors.GetAPIError(s3errors.ErrInvalidQueryParams)},
		{name: "empty", expires: []string{""}, err: s3errors.GetAPIError(s3errors.ErrMalformedExpires)},
		{name: "not a number", expires: []string{"abc"}, err: s3errors.GetAPIError(s3errors.ErrMalformedExpires)},
		{name: "duration unit", expires: []string{"5m"}, err: s3errors.GetAPIError(s3errors.ErrMalformedExpires)},
		{name: "fraction", expires: []string{"5.5"}, err: s3errors.GetAPIError(s3errors.ErrMalformedExpires)},
		{name: "negative", expires: []string{"-5"}, err: s3errors.GetAPIError(s3errors.ErrNegativeExpires)},
		{name: "above maximum", expires: []string{"604801"}, err: s3errors.GetAPIError(s3errors.ErrMaximumExpires)},
		{name: "duration overflow", expires: []string{"9223372036854775807"}, err: s3errors.GetAPIError(s3errors.ErrMaximumExpires)},
		// AWS S3 answers the same.
		{name: "int64 overflow", expires: []string{"9223372036854775808"}, err: s3errors.GetAPIError(s3errors.ErrMalformedExpires)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			date := time.Now().UTC()
			query := url.Values{
				AmzAlgorithm:     {"AWS4-HMAC-SHA256"},
				AmzCredential:    {accessKeyID + "/" + date.Format("20060102") + "/us-east-1/s3/aws4_request"},
				AmzDate:          {date.Format(timeFormatISO8601)},
				AmzSignedHeaders: {"host"},
				AmzSignature:     {"00"},
			}
			if tc.expires != nil {
				query[AmzExpires] = tc.expires
			}
			r := httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil)

			_, err := (&center{cli: &boxStub{}}).Authenticate(r)
			require.ErrorIs(t, err, tc.err)
		})
	}

	for _, param := range []string{AmzCredential, AmzSignature, AmzSignedHeaders} {
		t.Run("missing "+param, func(t *testing.T) {
			date := time.Now().UTC()
			query := url.Values{
				AmzAlgorithm:     {"AWS4-HMAC-SHA256"},
				AmzCredential:    {accessKeyID + "/" + date.Format("20060102") + "/us-east-1/s3/aws4_request"},
				AmzDate:          {date.Format(timeFormatISO8601)},
				AmzExpires:       {"3600"},
				AmzSignedHeaders: {"host"},
				AmzSignature:     {"00"},
			}
			query.Del(param)
			r := httptest.NewRequest(http.MethodGet, "/?"+query.Encode(), nil)

			cli := &boxStub{}
			_, err := (&center{cli: cli}).Authenticate(r)
			require.ErrorIs(t, err, s3errors.GetAPIError(s3errors.ErrInvalidQueryParams))
			require.Zero(t, cli.calls)
		})
	}
}

// Requests as sent by AWS SDK for Java 1.12.797: it signs every header it sends,
// "user-agent" included.
func TestCheckSignUserAgent(t *testing.T) {
	const (
		emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		userAgent   = "aws-sdk-java/1.12.797 Linux/5.4.0-216-generic OpenJDK_64-Bit_Server_VM/11.0.27+6-post-Ubuntu-0ubuntu120.04 java/11.0.27 vendor/Ubuntu cfg/retry-mode/standard cfg/auth-source#unknown m/P"
	)
	box := &accessbox.Box{Gate: &accessbox.GateData{AccessKey: "secretsecret"}}

	for _, tc := range []struct {
		name, method, target, date, signedHeaders, signature, payloadHash string
		contentLength                                                     int
		headers                                                           map[string]string
	}{
		{
			name:          "ListObjectsV2",
			method:        http.MethodGet,
			target:        "/bkt/?list-type=2&max-keys=100&prefix=p%2F&fetch-owner=false",
			date:          "20261116T072823Z",
			signedHeaders: "amz-sdk-invocation-id;amz-sdk-request;amz-sdk-retry;content-type;host;user-agent;x-amz-content-sha256;x-amz-date",
			signature:     "3b95d7020fb923e4eef263bb4b00a350075d7faedead205d0a83c893cf9cb1f4",
			payloadHash:   emptySHA256,
			headers: map[string]string{
				"Amz-Sdk-Invocation-Id": "cb923efa-1e43-545d-08fc-cd81d534665c",
				"Content-Type":          "application/octet-stream",
			},
		},
		{
			name:          "CopyObject",
			method:        http.MethodPut,
			target:        "/bkt/dst",
			date:          "20261116T071316Z",
			signedHeaders: "amz-sdk-invocation-id;amz-sdk-request;amz-sdk-retry;content-length;content-type;host;user-agent;x-amz-content-sha256;x-amz-copy-source;x-amz-date",
			signature:     "5cbc5f05fa0d572d6ed595d07944cb7b9471e911680611937db31cc56f4bf411",
			payloadHash:   emptySHA256,
			headers: map[string]string{
				"Amz-Sdk-Invocation-Id": "ea2d3397-2e11-f4a1-2c15-9809ae14f69a",
				"Content-Type":          "application/octet-stream",
				"X-Amz-Copy-Source":     "/bkt/k",
			},
		},
		{
			name:          "PutObject",
			method:        http.MethodPut,
			target:        "/bkt/k",
			date:          "20261116T071315Z",
			signedHeaders: "amz-sdk-invocation-id;amz-sdk-request;amz-sdk-retry;content-length;content-md5;content-type;host;user-agent;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-meta-a",
			signature:     "855965f3feaf7296183ce32c32bf92d0fd121ddc64c89b6299e93a621a4bbe81",
			payloadHash:   "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			contentLength: 1198,
			headers: map[string]string{
				"Amz-Sdk-Invocation-Id":        "4830b31d-95f6-b3fc-886f-21933086f1d1",
				"Content-Md5":                  "AlGmb1NJgdqDQ/akAY3JqA==",
				"Content-Type":                 "text/plain",
				"X-Amz-Decoded-Content-Length": "1024",
				"X-Amz-Meta-A":                 "b",
				"Expect":                       "100-continue",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signTime, err := time.Parse(timeFormatISO8601, tc.date)
			require.NoError(t, err)

			newRequest := func() (*http.Request, *authHeader) {
				r := httptest.NewRequest(tc.method, "http://127.0.0.1:19555"+tc.target, bytes.NewReader(make([]byte, tc.contentLength)))
				r.Header.Set("Content-Length", strconv.Itoa(tc.contentLength))
				r.Header.Set("X-Amz-Date", tc.date)
				r.Header.Set("X-Amz-Content-Sha256", tc.payloadHash)
				r.Header.Set("Amz-Sdk-Request", "attempt=1;max=1")
				r.Header.Set("Amz-Sdk-Retry", "0/0/500")
				r.Header.Set("User-Agent", userAgent)
				r.Header.Set("Connection", "Keep-Alive")
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				return r, &authHeader{
					AccessKeyID:  "AKIDEXAMPLE",
					Service:      "s3",
					Region:       "us-east-1",
					SignatureV4:  tc.signature,
					SignedFields: strings.Split(tc.signedHeaders, ";"),
					Date:         tc.date[:8],
					PayloadHash:  tc.payloadHash,
				}
			}
			c := &center{}

			r, hdr := newRequest()
			require.NoError(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime))

			r, hdr = newRequest()
			r.Header.Set("User-Agent", "other")
			require.ErrorIs(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime), s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))

			r, hdr = newRequest()
			r.URL.Path += "x"
			require.ErrorIs(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime), s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))
		})
	}
}

// signatureFromAuthHeader returns the Signature auth-param of an AWS4-HMAC-SHA256 Authorization
// header, empty if the scheme differs, there is no such param or the header is malformed.
func signatureFromAuthHeader(header string) string {
	scheme, params := splitCredentials(header)
	if !strings.EqualFold(scheme, signingAlgorithm) {
		return ""
	}
	for {
		name, value, err := params.next()
		if err != nil || name == "" {
			return ""
		}
		if strings.EqualFold(name, signatureParam) {
			return value
		}
	}
}

// BenchmarkCheckSign compares the gateway signature calculation with the signer
// from AWS SDK, the way it was used for the check before.
func BenchmarkCheckSign(b *testing.B) {
	const (
		secret      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		accessKeyID = "AKIAIOSFODNN7EXAMPLE"
		payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	var signTime = time.Date(2026, time.November, 17, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name, method, target string
		headers              map[string]string
	}{
		{
			name:   "GetObject",
			method: http.MethodGet,
			target: "/bucket/dir/object",
		},
		{
			name:   "ListObjectsV2",
			method: http.MethodGet,
			target: "/bucket?list-type=2&prefix=dir%2F&delimiter=%2F&max-keys=1000&encoding-type=url",
		},
		{
			name:   "PutObject",
			method: http.MethodPut,
			target: "/bucket/dir/object",
			headers: map[string]string{
				"Content-Type":          "application/octet-stream",
				"Content-Md5":           "MlvWDXg9Kyn9HDlfHyGcWg==",
				"Amz-Sdk-Invocation-Id": "cb923efa-1e43-545d-08fc-cd81d534665c",
				"Amz-Sdk-Request":       "attempt=1; max=3",
				"X-Amz-Meta-Key":        "value",
				"X-Amz-Meta-Other":      "other value",
				"X-Amz-Storage-Class":   "STANDARD",
				"X-Amz-Acl":             "private",
			},
		},
	} {
		r := httptest.NewRequest(tc.method, "http://s3.example.com:8080"+tc.target, nil)
		r.Header.Set("X-Amz-Date", signTime.Format(timeFormatISO8601))
		r.Header.Set("X-Amz-Content-Sha256", payloadHash)
		for k, v := range tc.headers {
			r.Header.Set(k, v)
		}

		var signedFields = []string{"host"}
		for k := range r.Header {
			signedFields = append(signedFields, strings.ToLower(k))
		}

		hdr := &authHeader{
			AccessKeyID:  accessKeyID,
			Service:      "s3",
			Region:       "us-east-1",
			SignedFields: signedFields,
			Date:         signTime.Format("20060102"),
			PayloadHash:  payloadHash,
		}

		var expected string

		b.Run(tc.name+"/SDK", func(b *testing.B) {
			request := cloneRequest(r, hdr)

			b.ReportAllocs()
			for b.Loop() {
				awsCreds, err := credentials.NewStaticCredentialsProvider(accessKeyID, secret, "").Retrieve(request.Context())
				require.NoError(b, err)

				signer := v4amz.NewSigner(func(signer *v4amz.SignerOptions) {
					signer.DisableURIPathEscaping = true
				})
				require.NoError(b, signer.SignHTTP(request.Context(), awsCreds, request, payloadHash, hdr.Service, hdr.Region, signTime))

				expected = signatureFromAuthHeader(request.Header.Get(AuthorizationHdr))
			}
		})

		b.Run(tc.name+"/gateway", func(b *testing.B) {
			var (
				request   = cloneRequest(r, hdr)
				signature string
			)

			b.ReportAllocs()
			for b.Loop() {
				signature = signHeaders(secret, hdr, request, signTime)
			}

			require.Equal(b, expected, signature)
		})
	}
}

// Header signatures made by the AWS SDK signer have to pass the check.
func TestCheckSignSDKSigner(t *testing.T) {
	const (
		secret      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	var (
		box      = &accessbox.Box{Gate: &accessbox.GateData{AccessKey: secret}}
		signTime = time.Date(2026, time.November, 17, 10, 0, 0, 0, time.UTC)
		signer   = v4amz.NewSigner(func(signer *v4amz.SignerOptions) {
			signer.DisableURIPathEscaping = true
		})
	)

	awsCreds, err := credentials.NewStaticCredentialsProvider("AKIAIOSFODNN7EXAMPLE", secret, "").Retrieve(context.Background())
	require.NoError(t, err)

	for _, tc := range []struct {
		name, method, target string
		body                 []byte
		headers              map[string][]string
	}{
		{
			name:   "no query",
			method: http.MethodGet,
			target: "/bucket/object",
		},
		{
			name:   "bucket root",
			method: http.MethodGet,
			target: "/",
		},
		{
			name:   "query order and repeated keys",
			method: http.MethodGet,
			target: "/bucket?prefix=b&list-type=2&prefix=a&delimiter=%2F&max-keys=100",
		},
		{
			name:   "query without value and with spaces",
			method: http.MethodPost,
			target: "/bucket/object?uploads=&x=a+b&y=c%20d&z=%2B",
		},
		{
			name:   "escaped path",
			method: http.MethodGet,
			target: "/bucket/dir%20with%20space/%D0%BA%D0%BB%D1%8E%D1%87/a%2Bb=c;d,e@f$g&h:i",
		},
		{
			name:   "body",
			method: http.MethodPut,
			target: "/bucket/object",
			body:   []byte("payload"),
			headers: map[string][]string{
				"Content-Type":   {"text/plain"},
				"Content-Md5":    {"MlvWDXg9Kyn9HDlfHyGcWg=="},
				"X-Amz-Meta-Key": {"value"},
			},
		},
		{
			name:   "spaces in values",
			method: http.MethodPut,
			target: "/bucket/object",
			headers: map[string][]string{
				"X-Amz-Meta-Spaces": {"  a   b  c "},
				"X-Amz-Meta-Tab":    {"a\tb \t c"},
				"X-Amz-Meta-Empty":  {""},
			},
		},
		{
			name:   "repeated header",
			method: http.MethodGet,
			target: "/bucket/object",
			headers: map[string][]string{
				"X-Amz-Meta-Multi": {"b", "a  a", "c"},
			},
		},
		{
			name:   "copy",
			method: http.MethodPut,
			target: "/bucket/copy",
			headers: map[string][]string{
				"X-Amz-Copy-Source":        {"/bucket/dir%20with%20space/object"},
				"X-Amz-Metadata-Directive": {"REPLACE"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payloadHash = emptySHA256
			if len(tc.body) > 0 {
				sum := sha256.Sum256(tc.body)
				payloadHash = hex.EncodeToString(sum[:])
			}

			r := httptest.NewRequest(tc.method, "http://s3.example.com:8080"+tc.target, bytes.NewReader(tc.body))
			r.Header.Set("Content-Length", strconv.Itoa(len(tc.body)))
			r.Header.Set("X-Amz-Date", signTime.Format(timeFormatISO8601))
			r.Header.Set("X-Amz-Content-Sha256", payloadHash)
			maps.Copy(r.Header, tc.headers)
			require.NoError(t, signer.SignHTTP(context.Background(), awsCreds, r, payloadHash, "s3", "us-east-1", signTime))

			authorization := r.Header.Get(AuthorizationHdr)
			_, signedHeaders, ok := strings.Cut(authorization, "SignedHeaders=")
			require.True(t, ok)
			signedHeaders, _, ok = strings.Cut(signedHeaders, ",")
			require.True(t, ok)

			// Not signed, must not affect the result.
			r.Header.Set("User-Agent", "client/1.0")
			r.Header.Set("Accept-Encoding", "identity")

			newAuthHeader := func() *authHeader {
				return &authHeader{
					AccessKeyID:  "AKIAIOSFODNN7EXAMPLE",
					Service:      "s3",
					Region:       "us-east-1",
					SignatureV4:  signatureFromAuthHeader(authorization),
					SignedFields: strings.Split(signedHeaders, ";"),
					Date:         signTime.Format("20060102"),
					PayloadHash:  payloadHash,
				}
			}
			c := &center{}

			hdr := newAuthHeader()
			require.NoError(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime))

			hdr = newAuthHeader()
			hdr.PayloadHash = strings.Repeat("0", 64)
			require.ErrorIs(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime), s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))

			hdr = newAuthHeader()
			r.Method = http.MethodDelete
			require.ErrorIs(t, c.checkSign(hdr, box, cloneRequest(r, hdr), signTime), s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))
		})
	}
}

func TestAuthenticatePresigned(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	var (
		accessKeyID = strings.ReplaceAll(oidtest.Address().String(), "/", "0")
		c           = &center{cli: &boxStub{box: &accessbox.Box{Gate: &accessbox.GateData{AccessKey: secret}}}}
		signer      = v4amz.NewSigner(func(signer *v4amz.SignerOptions) {
			signer.DisableURIPathEscaping = true
		})
	)

	awsCreds, err := credentials.NewStaticCredentialsProvider(accessKeyID, secret, "").Retrieve(context.Background())
	require.NoError(t, err)

	for _, tc := range []struct {
		name          string
		headers       map[string]string
		signedHeaders string
		noHoisting    bool
	}{
		{
			name:          "host",
			signedHeaders: "host",
		},
		{
			name: "several headers",
			headers: map[string]string{
				"Content-Type":   "text/plain",
				"X-Amz-Meta-Key": "value",
			},
			signedHeaders: "content-type;host;x-amz-meta-key",
		},
		{
			name: "header kept out of the query",
			headers: map[string]string{
				"X-Amz-Expected-Bucket-Owner": "owner",
			},
			signedHeaders: "host;x-amz-expected-bucket-owner",
			noHoisting:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			presigned, err := http.NewRequest(http.MethodPut, "http://s3.example.com:8080/bucket/object?X-Amz-Expires=600", nil)
			require.NoError(t, err)
			for k, v := range tc.headers {
				presigned.Header.Set(k, v)
			}

			uri, _, err := signer.PresignHTTP(context.Background(), awsCreds, presigned, UnsignedPayload, "s3", "us-east-1", time.Now(), func(o *v4amz.SignerOptions) {
				o.DisableHeaderHoisting = tc.noHoisting
			})
			require.NoError(t, err)

			newRequest := func() *http.Request {
				r := httptest.NewRequest(http.MethodPut, uri, strings.NewReader("payload"))
				r.Header.Set("Content-Length", "7")
				// Not signed, must not affect the result.
				r.Header.Set("User-Agent", "client/1.0")
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				return r
			}

			r := newRequest()
			require.Equal(t, tc.signedHeaders, r.URL.Query().Get(AmzSignedHeaders))

			_, err = c.Authenticate(r)
			require.NoError(t, err)

			for k := range tc.headers {
				r = newRequest()
				r.Header.Set(k, "other")

				_, err = c.Authenticate(r)
				require.ErrorIs(t, err, s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))
			}
		})
	}
}

// The SDK signer never signs a zero Content-Length or User-Agent, the signature
// is made by hand here.
func TestAuthenticatePresignedContentLengthUserAgent(t *testing.T) {
	const (
		secret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		userAgent = "client/1.0"
	)

	var (
		accessKeyID = strings.ReplaceAll(oidtest.Address().String(), "/", "0")
		c           = &center{cli: &boxStub{box: &accessbox.Box{Gate: &accessbox.GateData{AccessKey: secret}}}}
		signTime    = time.Now().UTC()
		date        = signTime.Format(timeFormatISO8601)
		scope       = signTime.Format("20060102") + "/us-east-1/s3/aws4_request"
		query       = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
			"&X-Amz-Credential=" + accessKeyID + "%2F" + strings.ReplaceAll(scope, "/", "%2F") +
			"&X-Amz-Date=" + date +
			"&X-Amz-Expires=600" +
			"&X-Amz-SignedHeaders=content-length%3Bhost%3Buser-agent"
		canonical = "PUT\n" +
			"/bucket/object\n" +
			query + "\n" +
			"content-length:0\n" +
			"host:s3.example.com:8080\n" +
			"user-agent:" + userAgent + "\n" +
			"\n" +
			"content-length;host;user-agent\n" +
			UnsignedPayload
		sum       = sha256.Sum256([]byte(canonical))
		strToSign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
		uri       = "http://s3.example.com:8080/bucket/object?" + query + "&X-Amz-Signature=" + signStr(secret, "s3", "us-east-1", signTime, strToSign)
	)

	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPut, uri, http.NoBody)
		r.Header.Set("Content-Length", "0")
		r.Header.Set("User-Agent", userAgent)
		// Not signed, must not affect the result.
		r.Header.Set("Content-Type", "text/plain")
		return r
	}

	_, err := c.Authenticate(newRequest())
	require.NoError(t, err)

	for _, k := range []string{"Content-Length", "User-Agent"} {
		r := newRequest()
		r.Header.Set(k, "1")

		_, err = c.Authenticate(r)
		require.ErrorIs(t, err, s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch))
	}
}

// A signature not covering the host is valid for any bucket addressed in the
// virtual-hosted style, it must not be accepted even if it is correct.
func TestAuthenticateHostNotSigned(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	var (
		accessKeyID = strings.ReplaceAll(oidtest.Address().String(), "/", "0")
		c           = &center{cli: &boxStub{box: &accessbox.Box{Gate: &accessbox.GateData{AccessKey: secret}}}}
		signTime    = time.Now().UTC()
		date        = signTime.Format(timeFormatISO8601)
		scope       = signTime.Format("20060102") + "/us-east-1/s3/aws4_request"
	)

	sign := func(canonical string) string {
		sum := sha256.Sum256([]byte(canonical))
		return signStr(secret, "s3", "us-east-1", signTime, "AWS4-HMAC-SHA256\n"+date+"\n"+scope+"\n"+hex.EncodeToString(sum[:]))
	}

	for _, tc := range []struct {
		name          string
		signedHeaders string
		err           error
	}{
		{name: "signed", signedHeaders: "host;x-amz-date"},
		{name: "not signed", signedHeaders: "x-amz-date", err: s3errors.GetAPIError(s3errors.ErrSignatureDoesNotMatch)},
	} {
		var headers = "x-amz-date:" + date + "\n"
		if tc.err == nil {
			headers = "host:bucket.s3.example.com\n" + headers
		}

		t.Run("header/"+tc.name, func(t *testing.T) {
			signature := sign("GET\n/object\n\n" + headers + "\n" + tc.signedHeaders + "\n" + emptyStringSHA256)

			r := httptest.NewRequest(http.MethodGet, "http://bucket.s3.example.com/object", nil)
			r.Header.Set(AmzDate, date)
			r.Header.Set(AuthorizationHdr, "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/"+scope+
				", SignedHeaders="+tc.signedHeaders+", Signature="+signature)

			_, err := c.Authenticate(r)
			require.ErrorIs(t, err, tc.err)
		})

		t.Run("presigned/"+tc.name, func(t *testing.T) {
			query := "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
				"&X-Amz-Credential=" + accessKeyID + "%2F" + strings.ReplaceAll(scope, "/", "%2F") +
				"&X-Amz-Date=" + date +
				"&X-Amz-Expires=600" +
				"&X-Amz-SignedHeaders=" + strings.ReplaceAll(tc.signedHeaders, ";", "%3B")
			signature := sign("GET\n/object\n" + query + "\n" + headers + "\n" + tc.signedHeaders + "\n" + UnsignedPayload)

			r := httptest.NewRequest(http.MethodGet, "http://bucket.s3.example.com/object?"+query+"&X-Amz-Signature="+signature, nil)
			r.Header.Set(AmzDate, date)

			_, err := c.Authenticate(r)
			require.ErrorIs(t, err, tc.err)
		})
	}
}
