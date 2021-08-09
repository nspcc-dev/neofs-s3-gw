package auth

import (
	"strings"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/stretchr/testify/require"
)

func TestAuthHeaderParse(t *testing.T) {
	defaultHeader := "AWS4-HMAC-SHA256 Credential=oid0cid/20210809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=2811ccb9e242f41426738fb1f"

	center := &center{
		reg: &regexpSubmatcher{re: authorizationFieldRegexp},
	}

	for _, tc := range []struct {
		header   string
		err      error
		expected *authHeader
	}{
		{
			header: defaultHeader,
			err:    nil,
			expected: &authHeader{
				AccessKeyID:  "oid0cid",
				Service:      "s3",
				Region:       "us-east-1",
				SignatureV4:  "2811ccb9e242f41426738fb1f",
				SignedFields: []string{"host", "x-amz-content-sha256", "x-amz-date"},
				Date:         "20210809",
			},
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "Signature=2811ccb9e242f41426738fb1f", ""),
			err:      errors.GetAPIError(errors.ErrAuthorizationHeaderMalformed),
			expected: nil,
		},
		{
			header:   strings.ReplaceAll(defaultHeader, "oid0cid", "oidcid"),
			err:      errors.GetAPIError(errors.ErrInvalidAccessKeyID),
			expected: nil,
		},
	} {
		authHeader, err := center.parseAuthHeader(tc.header)
		require.Equal(t, tc.err, err, tc.header)
		require.Equal(t, tc.expected, authHeader, tc.header)
	}
}

func TestAuthHeaderGetAddress(t *testing.T) {
	defaulErr := errors.GetAPIError(errors.ErrInvalidAccessKeyID)

	for _, tc := range []struct {
		authHeader *authHeader
		err        error
	}{
		{
			authHeader: &authHeader{
				AccessKeyID: "vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJM0HrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB",
			},
			err: nil,
		},
		{
			authHeader: &authHeader{
				AccessKeyID: "vWqF8cMDRbJcvnPLALoQGnABPPhw8NyYMcGsfDPfZJMHrgjonN8CgFvCZ3kh9BUXw4W2tJ5E7EAGhueSF122HB",
			},
			err: defaulErr,
		},
		{
			authHeader: &authHeader{
				AccessKeyID: "oid0cid",
			},
			err: defaulErr,
		},
		{
			authHeader: &authHeader{
				AccessKeyID: "oidcid",
			},
			err: defaulErr,
		},
	} {
		_, err := tc.authHeader.getAddress()
		require.Equal(t, tc.err, err, tc.authHeader.AccessKeyID)
	}
}
