package auth

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/nspcc-dev/neofs-s3-gw/api/auth/signer/v4"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/stretchr/testify/require"
)

func TestAuthHeaderParse(t *testing.T) {
	defaultHeader := "AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2811ccb9e242f41426738fb1f"

	center := &center{
		reg: NewRegexpMatcher(authorizationFieldRegexp),
	}

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
	} {
		authHeader, err := center.parseAuthHeader(tc.header)
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

// TestAwsEncodedChunkReader checks example from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
func TestAwsEncodedChunkReader(t *testing.T) {
	chunkOnePayload := make([]byte, 65536)
	for i := 0; i < 65536; i++ {
		chunkOnePayload[i] = 'a'
	}

	chunkOneBody := append([]byte("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\n"), chunkOnePayload...)
	awsCreds := credentials.NewStaticCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "")

	ts, err := time.Parse(timeFormatISO8601, "20130524T000000Z")
	require.NoError(t, err)

	seedSignature, err := hex.DecodeString("4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
	require.NoError(t, err)

	chunkTwoPayload := make([]byte, 1024)
	for i := 0; i < 1024; i++ {
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

		require.Equal(t, append(chunkOnePayload, chunkTwoPayload...), payload.Bytes())
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

		require.ErrorIs(t, err, v4.ErrMissingSeparator)
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

		require.ErrorIs(t, err, v4.ErrNoChunksSeparator)
	})

	t.Run("err chunk header too long", func(t *testing.T) {
		streamSigner := v4.NewChunkSigner("us-east-1", "s3", seedSignature, ts, awsCreds)
		chunkThreeBody := make([]byte, 4097)
		for i := 0; i < len(chunkThreeBody); i++ {
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

	host := "http://localhost:19080"
	bucketName := "heh1701422026"
	fileName := strconv.FormatInt(time.Now().Unix(), 16)
	totalPayloadLength := 66560
	chunkSize := 65536

	payload := make([]byte, totalPayloadLength)
	for i := 0; i < totalPayloadLength; i++ {
		payload[i] = 'a'
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/%s/%s.txt", host, bucketName, fileName), nil)
	require.NoError(t, err)

	tsISO8601 := ts.Format(timeFormatISO8601)

	req.Header.Set("x-amz-date", tsISO8601)
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.Header.Set("content-encoding", "aws-chunked")
	req.Header.Set("x-amz-decoded-content-length", strconv.Itoa(totalPayloadLength))

	awsCreds := credentials.NewStaticCredentials(
		"6cpBf2jzHdD2MJHsjwLuVYYDAPJcfsJ5oufJWnHhrSBQ0FPjWXxmLmvKDAyhr1SEwnfKLJq3twKzuWG7f24qfyWcD", // access_key_id
		"79488f248493cb5175ea079a12a3e08015021d9c710a064017e1da6a2b0ae111",                          // secret_access_key
		"")

	signer := v4.NewSigner(awsCreds)

	signer.DisableURIPathEscaping = true
	_, err = signer.Sign(req, nil, "s3", "us-east-1", ts)
	require.NoError(t, err)

	reg := NewRegexpMatcher(authorizationFieldRegexp)
	signature := reg.GetSubmatches(req.Header.Get(AuthorizationHdr))["v4_signature"]

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

	_, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
}

func chunkSlice(payload []byte, chunkSize int) [][]byte {
	var result [][]byte

	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize

		if end > len(payload) {
			end = len(payload)
		}

		result = append(result, payload[i:end])
	}

	return result
}
