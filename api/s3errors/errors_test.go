package s3errors

import (
	"errors"
	"testing"
)

func BenchmarkErrCode(b *testing.B) {
	err := GetAPIError(ErrNoSuchKey)

	for range b.N {
		if IsS3Error(err, ErrNoSuchKey) {
			_ = err
		}
	}
}

func BenchmarkErrorsIs(b *testing.B) {
	err := GetAPIError(ErrNoSuchKey)

	for range b.N {
		if errors.Is(err, GetAPIError(ErrNoSuchKey)) {
			_ = err
		}
	}
}
