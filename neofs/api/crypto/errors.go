package crypto

import "fmt"

// Error is the generic type for any error happening during decrypting
// an object. It indicates that the object itself or its metadata was
// modified accidentally or maliciously.
type Error struct {
	err error
}

// Errorf - formats according to a format specifier and returns
// the string as a value that satisfies error of type crypto.Error
func Errorf(format string, a ...interface{}) error {
	return Error{err: fmt.Errorf(format, a...)}
}

// Unwrap the internal error.
func (e Error) Unwrap() error { return e.err }

// Error 'error' compatible method.
func (e Error) Error() string {
	if e.err == nil {
		return "crypto: cause <nil>"
	}
	return e.err.Error()
}

var (
	// ErrInvalidEncryptionMethod indicates that the specified SSE encryption method
	// is not supported.
	ErrInvalidEncryptionMethod = Errorf("The encryption method is not supported")

	// ErrInvalidCustomerAlgorithm indicates that the specified SSE-C algorithm
	// is not supported.
	ErrInvalidCustomerAlgorithm = Errorf("The SSE-C algorithm is not supported")

	// ErrMissingCustomerKey indicates that the HTTP headers contains no SSE-C client key.
	ErrMissingCustomerKey = Errorf("The SSE-C request is missing the customer key")

	// ErrMissingCustomerKeyMD5 indicates that the HTTP headers contains no SSE-C client key
	// MD5 checksum.
	ErrMissingCustomerKeyMD5 = Errorf("The SSE-C request is missing the customer key MD5")

	// ErrInvalidCustomerKey indicates that the SSE-C client key is not valid - e.g. not a
	// base64-encoded string or not 256 bits long.
	ErrInvalidCustomerKey = Errorf("The SSE-C client key is invalid")

	// ErrSecretKeyMismatch indicates that the provided secret key (SSE-C client key / SSE-S3 KMS key)
	// does not match the secret key used during encrypting the object.
	ErrSecretKeyMismatch = Errorf("The secret key does not match the secret key used during upload")

	// ErrCustomerKeyMD5Mismatch indicates that the SSE-C key MD5 does not match the
	// computed MD5 sum. This means that the client provided either the wrong key for
	// a certain MD5 checksum or the wrong MD5 for a certain key.
	ErrCustomerKeyMD5Mismatch = Errorf("The provided SSE-C key MD5 does not match the computed MD5 of the SSE-C key")
	// ErrIncompatibleEncryptionMethod indicates that both SSE-C headers and SSE-S3 headers were specified, and are incompatible
	// The client needs to remove the SSE-S3 header or the SSE-C headers
	ErrIncompatibleEncryptionMethod = Errorf("Server side encryption specified with both SSE-C and SSE-S3 headers")

	// ErrKMSAuthLogin is raised when there is a failure authenticating to KMS
	ErrKMSAuthLogin = Errorf("Vault service did not return auth info")
)
