package v4

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// StreamSigner implements signing of event stream encoded payloads.
type StreamSigner struct {
	region  string
	service string

	credentials aws.Credentials

	prevSig []byte
}

// NewStreamSigner creates a SigV4 signer used to sign Event Stream encoded messages.
func NewStreamSigner(region, service string, seedSignature []byte, credentials aws.Credentials) *StreamSigner {
	return &StreamSigner{
		region:      region,
		service:     service,
		credentials: credentials,
		prevSig:     seedSignature,
	}
}

// GetSignature takes an event stream encoded headers and payload and returns a signature.
func (s *StreamSigner) GetSignature(headers, payload []byte, date time.Time) ([]byte, error) {
	sigKey := deriveSigningKey(s.region, s.service, s.credentials.SecretAccessKey, date)

	keyPath := buildSigningScope(s.region, s.service, date)

	stringToSign := buildEventStreamStringToSign(headers, payload, s.prevSig, keyPath, date)

	signature := hmacSHA256(sigKey, []byte(stringToSign))
	s.prevSig = signature

	return signature, nil
}

func buildEventStreamStringToSign(headers, payload, prevSig []byte, scope string, date time.Time) string {
	return strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		formatTime(date),
		scope,
		hex.EncodeToString(prevSig),
		hex.EncodeToString(hashSHA256(headers)),
		hex.EncodeToString(hashSHA256(payload)),
	}, "\n")
}
