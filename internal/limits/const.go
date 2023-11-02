package limits

import (
	"time"
)

const (
	// MaxPreSignedLifetime describes maximum TTL for presigned url.
	// 7 days, according to https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html.
	MaxPreSignedLifetime = 7 * 24 * time.Hour
)
