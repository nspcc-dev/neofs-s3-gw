package handler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckBucketName(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  bool
	}{
		{name: "bucket"},
		{name: "2bucket"},
		{name: "buc.ket"},
		{name: "buc-ket"},
		{name: "abc"},
		{name: "63aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "buc.-ket", err: true},
		{name: "bucket.", err: true},
		{name: ".bucket", err: true},
		{name: "bucket.", err: true},
		{name: "bucket-", err: true},
		{name: "-bucket", err: true},
		{name: "Bucket", err: true},
		{name: "buc.-ket", err: true},
		{name: "buc-.ket", err: true},
		{name: "Bucket", err: true},
		{name: "buc!ket", err: true},
		{name: "buc_ket", err: true},
		{name: "xn--bucket", err: true},
		{name: "bucket-s3alias", err: true},
		{name: "192.168.0.1", err: true},
		{name: "as", err: true},
		{name: "64aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", err: true},
	} {
		err := checkBucketName(tc.name)
		if tc.err {
			require.Error(t, err, "bucket name: %s", tc.name)
		} else {
			require.NoError(t, err, "bucket name: %s", tc.name)
		}
	}
}
