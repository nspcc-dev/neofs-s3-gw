package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
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

func TestCreateBucketWithNamespace(t *testing.T) {
	type (
		data struct {
			name       string
			namespace  string
			bktName    string
			wantDomain string
		}
	)

	for _, tc := range []data{
		{
			name:       "without namespace",
			bktName:    "bucket-no-ns",
			wantDomain: "bucket-no-ns",
		},
		{
			name:       "with namespace",
			namespace:  "customns",
			bktName:    "bucket-with-ns",
			wantDomain: "bucket-with-ns.customns",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hc := prepareHandlerContext(t)

			box := newTestAccessBox(t, nil)
			box.Namespace = tc.namespace

			w, r := prepareTestRequest(hc, tc.bktName, "", nil)
			r = r.WithContext(context.WithValue(r.Context(), api.BoxData, box))
			hc.Handler().CreateBucketHandler(w, r)
			assertStatus(t, w, http.StatusOK)

			cnrID, err := hc.MockedPool().ContainerID(tc.bktName, tc.namespace)
			require.NoError(t, err)

			cnr, err := hc.MockedPool().Container(hc.Context(), cnrID)
			require.NoError(t, err)
			require.Equal(t, tc.bktName, cnr.Name())

			domain := cnr.ReadDomain()
			require.Equal(t, tc.wantDomain, domain.Name())
		})
	}
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

// putBucketSettingsBehindCache changes bucket settings the way another gateway
// would: the container revision grows while the locally cached bucket info,
// settings included, stays as it was.
func putBucketSettingsBehindCache(t *testing.T, hc *handlerContext, bktInfo *data.BucketInfo, settings *data.BucketSettings) {
	payload, err := json.Marshal(settings)
	require.NoError(t, err)

	require.NoError(t, hc.MockedPool().SetContainerAttribute(hc.Context(), bktInfo.CID, "S3_SETTINGS", string(payload), nil))
}

func TestPutObjectRetriesOnContainerRevisionMismatch(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-revision-retry", "object"
	bktInfo := createTestBucket(hc, bktName)

	putBucketSettingsBehindCache(t, hc, bktInfo, &data.BucketSettings{Versioning: data.VersioningEnabled})

	hc.MockedPool().SetSearchRevisionMismatch(1)

	const content = "content"

	w, r := prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte(content)))
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	// The retry re-read the container, so the object went the versioned way.
	require.NotEmpty(t, w.Header().Get(api.AmzVersionID))

	refreshed, err := hc.Layer().GetBucketInfo(hc.Context(), bktName)
	require.NoError(t, err)
	require.True(t, refreshed.Settings.VersioningEnabled())
	require.Equal(t, refreshed.Revision, bktInfo.Revision+1)

	// The retry replayed the payload from the start. Anything reading the body
	// before the mismatch is reported would store a truncated object here.
	w, r = prepareTestRequest(hc, bktName, objName, nil)
	hc.Handler().GetObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	stored := w.Result().Body
	defer stored.Close()

	body, err := io.ReadAll(stored)
	require.NoError(t, err)
	require.Equal(t, content, string(body))
}

func TestPutObjectNoRetryOnWriteTimeRevisionMismatch(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-revision-no-retry", "object"
	bktInfo := createTestBucket(hc, bktName)

	putBucketSettingsBehindCache(t, hc, bktInfo, &data.BucketSettings{Versioning: data.VersioningEnabled})

	// Nothing rejects the request until the payload has been streamed, so the layer
	// does not report it as repeatable and the client is told to retry itself.
	w, r := prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte("content")))
	hc.Handler().PutObjectHandler(w, r)
	assertS3Error(t, w, s3errors.GetAPIError(s3errors.ErrOperationAborted))
}

func TestPutObjectRetriesOnce(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-revision-retry-once", "object"
	createTestBucket(hc, bktName)

	hc.MockedPool().SetSearchRevisionMismatch(putObjectExtraAttempts + 1)

	w, r := prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte("content")))
	hc.Handler().PutObjectHandler(w, r)
	assertS3Error(t, w, s3errors.GetAPIError(s3errors.ErrOperationAborted))
}

func TestPostObjectRetriesOnContainerRevisionMismatch(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-revision-retry-post", "object"
	bktInfo := createTestBucket(hc, bktName)

	putBucketSettingsBehindCache(t, hc, bktInfo, &data.BucketSettings{Versioning: data.VersioningEnabled})
	hc.MockedPool().SetSearchRevisionMismatch(1)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, defaultURL, nil)
	r.MultipartForm = &multipart.Form{Value: map[string][]string{
		"key":  {objName},
		"file": {"content"},
	}}
	reqInfo := api.NewReqInfo(w, r, api.ObjectRequest{Bucket: bktName, Object: objName})
	r = r.WithContext(api.SetReqInfo(hc.Context(), reqInfo))

	hc.Handler().PostObject(w, r)
	assertStatus(t, w, http.StatusNoContent)

	require.NotEmpty(t, w.Header().Get(api.AmzVersionID))
}

func TestTransformToS3ErrorRevisionMismatch(t *testing.T) {
	err := transformToS3Error(fmt.Errorf("put object: %w", apistatus.ErrContainerRevisionMismatch))

	s3err, ok := errors.AsType[s3errors.Error](err)
	require.True(t, ok)
	require.Equal(t, s3errors.ErrOperationAborted, s3err.ErrCode)
}
