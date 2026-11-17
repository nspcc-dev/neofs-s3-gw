package limits

import (
	"time"
)

const (
	// MaxPreSignedLifetime describes maximum TTL for presigned url.
	// 7 days, according to https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html.
	MaxPreSignedLifetime = 7 * 24 * time.Hour

	// MaxClockSkew is the maximum allowed difference between the request time and the gateway time.
	// 15 minutes, according to https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html.
	MaxClockSkew = 15 * time.Minute

	// MaxAccessBoxSize is the maximum payload size of an access box object.
	MaxAccessBoxSize = 65536 // 64 KB.
)
