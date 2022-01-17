package handler

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
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

func TestCustomJSONMarshal(t *testing.T) {
	data := []byte(`
{ "expiration": "2015-12-30T12:00:00.000Z",
  "conditions": [
	["content-length-range", 1048576, 10485760],
    {"bucket": "bucketName"},
    ["starts-with", "$key", "user/user1/"]
  ]
}`)

	parsedTime, err := time.Parse(time.RFC3339, "2015-12-30T12:00:00.000Z")
	require.NoError(t, err)

	expectedPolicy := &postPolicy{
		Expiration: parsedTime,
		Conditions: []*policyCondition{
			{
				Matching: "content-length-range",
				Key:      "1048576",
				Value:    "10485760",
			},
			{
				Matching: "eq",
				Key:      "bucket",
				Value:    "bucketName",
			},
			{
				Matching: "starts-with",
				Key:      "key",
				Value:    "user/user1/",
			},
		},
	}

	policy := &postPolicy{}
	err = json.Unmarshal(data, policy)
	require.NoError(t, err)

	require.Equal(t, expectedPolicy, policy)
}

func TestEmptyPostPolicy(t *testing.T) {
	r := &http.Request{
		MultipartForm: &multipart.Form{
			Value: map[string][]string{
				"key": {"some-key"},
			},
		},
	}
	reqInfo := &api.ReqInfo{}
	metadata := make(map[string]string)

	_, err := checkPostPolicy(r, reqInfo, metadata)
	require.NoError(t, err)
}
