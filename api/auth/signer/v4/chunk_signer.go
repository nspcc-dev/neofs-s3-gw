package v4

import (
	"encoding/hex"
	"hash"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	// precalculated hash for the zero chunk length.
	emptyChunkSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ChunkSigner implements signing of aws-chunked payloads.
type ChunkSigner struct {
	region  string
	service string

	credentials aws.Credentials

	prevSig  []byte
	seedDate time.Time
}

// NewChunkSigner creates a SigV4 signer used to sign Event Stream encoded messages.
func NewChunkSigner(region, service string, seedSignature []byte, seedDate time.Time, credentials aws.Credentials) *ChunkSigner {
	return &ChunkSigner{
		region:      region,
		service:     service,
		credentials: credentials,
		seedDate:    seedDate,
		prevSig:     seedSignature,
	}
}

// GetSignature takes an event stream encoded headers and payload and returns a signature.
func (s *ChunkSigner) GetSignature(payload []byte) ([]byte, error) {
	return s.getSignature(hashSHA256(payload))
}

// GetSignatureByHash takes an event stream encoded headers and payload and returns a signature.
func (s *ChunkSigner) GetSignatureByHash(payloadHash hash.Hash) ([]byte, error) {
	return s.getSignature(payloadHash.Sum(nil))
}

func (s *ChunkSigner) getSignature(payloadHash []byte) ([]byte, error) {
	sigKey := deriveSigningKey(s.region, s.service, s.credentials.SecretAccessKey, s.seedDate)

	keyPath := buildSigningScope(s.region, s.service, s.seedDate)

	stringToSign := buildStringToSign(payloadHash, s.prevSig, keyPath, s.seedDate)

	signature := hmacSHA256(sigKey, []byte(stringToSign))
	s.prevSig = signature

	return signature, nil
}

// GetTrailerSignature returns the signature of the trailing headers that close
// a STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER payload. The trailer must be in
// its canonical form: one "name:value\n" line per header. It continues the
// signature chain, so it must be called after the final zero-length chunk.
func (s *ChunkSigner) GetTrailerSignature(trailer []byte) []byte {
	sigKey := deriveSigningKey(s.region, s.service, s.credentials.SecretAccessKey, s.seedDate)

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER",
		formatTime(s.seedDate),
		buildSigningScope(s.region, s.service, s.seedDate),
		hex.EncodeToString(s.prevSig),
		hex.EncodeToString(hashSHA256(trailer)),
	}, "\n")

	signature := hmacSHA256(sigKey, []byte(stringToSign))
	s.prevSig = signature

	return signature
}

func buildStringToSign(payloadHash, prevSig []byte, scope string, date time.Time) string {
	return strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		formatTime(date),
		scope,
		hex.EncodeToString(prevSig),
		emptyChunkSHA256,
		hex.EncodeToString(payloadHash),
	}, "\n")
}
