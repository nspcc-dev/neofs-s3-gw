package v4

import (
	"encoding/hex"
	"hash"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	// precalculated hash for the zero chunk length.
	emptyChunkSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ChunkSigner implements signing of aws-chunked payloads.
type ChunkSigner struct {
	region  string
	service string

	credentials credentialValueProvider

	prevSig  []byte
	seedDate time.Time
}

// NewChunkSigner creates a SigV4 signer used to sign Event Stream encoded messages.
func NewChunkSigner(region, service string, seedSignature []byte, seedDate time.Time, credentials *credentials.Credentials) *ChunkSigner {
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
	credValue, err := s.credentials.Get()
	if err != nil {
		return nil, err
	}

	sigKey := deriveSigningKey(s.region, s.service, credValue.SecretAccessKey, s.seedDate)

	keyPath := buildSigningScope(s.region, s.service, s.seedDate)

	stringToSign := buildStringToSign(payloadHash, s.prevSig, keyPath, s.seedDate)

	signature := hmacSHA256(sigKey, []byte(stringToSign))
	s.prevSig = signature

	return signature, nil
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
