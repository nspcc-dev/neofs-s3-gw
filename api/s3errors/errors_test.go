package s3errors

import (
	"errors"
	"testing"
)

func BenchmarkErrCode(b *testing.B) {
	err := GetAPIError(ErrNoSuchKey)

	for b.Loop() {
		if IsS3Error(err, ErrNoSuchKey) {
			_ = err
		}
	}
}

func BenchmarkErrorsIs(b *testing.B) {
	err := GetAPIError(ErrNoSuchKey)

	for b.Loop() {
		if errors.Is(err, GetAPIError(ErrNoSuchKey)) {
			_ = err
		}
	}
}
