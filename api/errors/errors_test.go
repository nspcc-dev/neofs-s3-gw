package errors

import (
	"errors"
	"testing"
)

func BenchmarkErrCode(b *testing.B) {
	err := GetAPIError(ErrNoSuchKey)

	for i := 0; i < b.N; i++ {
		if IsS3Error(err, ErrNoSuchKey) {
			_ = err
		}
	}
}

func BenchmarkErrorsIs(b *testing.B) {
	err := GetAPIError(ErrNoSuchKey)

	for i := 0; i < b.N; i++ {
		if errors.Is(err, GetAPIError(ErrNoSuchKey)) {
			_ = err
		}
	}
}
