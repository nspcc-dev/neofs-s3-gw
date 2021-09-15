package errors

import (
	"fmt"
)

type (
	// ErrorCode type of error status.
	ErrorCode int

	// Error structure represents API error.
	Error struct {
		ErrCode        ErrorCode
		Code           string
		Description    string
		HTTPStatusCode int
	}
)

const maxEConfigJSONSize = 262272

// IsS3Error check if the provided error is a specific s3 error.
func IsS3Error(err error, code ErrorCode) bool {
	e, ok := err.(Error)
	return ok && e.ErrCode == code
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %d => %s", e.Code, e.HTTPStatusCode, e.Description)
}

// ObjectError - error that linked to specific object.
type ObjectError struct {
	Err     error
	Object  string
	Version string
}

func (e ObjectError) Error() string {
	return fmt.Sprintf("%s (%s:%s)", e.Err, e.Object, e.Version)
}

// ObjectVersion get "object:version" string.
func (e ObjectError) ObjectVersion() string {
	return e.Object + ":" + e.Version
}
