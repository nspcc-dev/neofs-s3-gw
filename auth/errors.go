package auth

import "fmt"

const (
	// Minimum length for MinIO access key.
	accessKeyMinLen = 3

	// Minimum length for MinIO secret key for both server and gateway mode.
	secretKeyMinLen = 8
)

// Common errors generated for access and secret key validation.
var (
	ErrInvalidAccessKeyLength = fmt.Errorf("access key must be minimum %v or more characters long", accessKeyMinLen)
	ErrInvalidSecretKeyLength = fmt.Errorf("secret key must be minimum %v or more characters long", secretKeyMinLen)
)
