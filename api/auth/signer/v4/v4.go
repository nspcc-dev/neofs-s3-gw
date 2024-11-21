package v4

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"time"
)

const (
	timeFormat      = "20060102T150405Z"
	shortTimeFormat = "20060102"
	awsV4Request    = "aws4_request"
)

func hmacSHA256(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func hashSHA256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func buildSigningScope(region, service string, dt time.Time) string {
	return strings.Join([]string{
		formatShortTime(dt),
		region,
		service,
		awsV4Request,
	}, "/")
}

func deriveSigningKey(region, service, secretKey string, dt time.Time) []byte {
	hmacDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(formatShortTime(dt)))
	hmacRegion := hmacSHA256(hmacDate, []byte(region))
	hmacService := hmacSHA256(hmacRegion, []byte(service))
	signingKey := hmacSHA256(hmacService, []byte(awsV4Request))
	return signingKey
}

func formatShortTime(dt time.Time) string {
	return dt.UTC().Format(shortTimeFormat)
}

func formatTime(dt time.Time) string {
	return dt.UTC().Format(timeFormat)
}
