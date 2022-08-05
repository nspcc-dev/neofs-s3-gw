package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/stretchr/testify/require"
)

func TestParseContinuationToken(t *testing.T) {
	var err error

	t.Run("empty token", func(t *testing.T) {
		var queryValues = map[string][]string{
			"continuation-token": {""},
		}
		_, err = parseContinuationToken(queryValues)
		require.Error(t, err)
	})

	t.Run("invalid not empty token", func(t *testing.T) {
		var queryValues = map[string][]string{
			"continuation-token": {"asd"},
		}
		_, err = parseContinuationToken(queryValues)
		require.Error(t, err)
	})

	t.Run("valid token", func(t *testing.T) {
		tokenStr := "75BTT5Z9o79XuKdUeGqvQbqDnxu6qWcR5EhxW8BXFf8t"
		var queryValues = map[string][]string{
			"continuation-token": {tokenStr},
		}
		token, err := parseContinuationToken(queryValues)
		require.NoError(t, err)
		require.Equal(t, tokenStr, token)
	})
}

func TestListObjectNullVersions(t *testing.T) {
	ctx := context.Background()
	hc := prepareHandlerContext(t)

	bktName := "bucket-versioning-enabled"
	createTestBucket(ctx, t, hc, bktName)

	objName := "object"

	body := bytes.NewReader([]byte("content"))
	w, r := prepareTestPayloadRequest(bktName, objName, body)
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	versioning := &VersioningConfiguration{Status: "Enabled"}
	w, r = prepareTestRequest(t, bktName, objName, versioning)
	hc.Handler().PutBucketVersioningHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	body2 := bytes.NewReader([]byte("content2"))
	w, r = prepareTestPayloadRequest(bktName, objName, body2)
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	hc.Handler().ListBucketObjectVersionsHandler(w, r)

	result := &ListObjectsVersionsResponse{}
	parseTestResponse(t, w, result)

	require.Len(t, result.Version, 2)
	require.Equal(t, data.UnversionedObjectVersionID, result.Version[1].VersionID)
}

func TestS3CompatibilityBucketListV2BothContinuationTokenStartAfter(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName := "bucket-for-listing"
	objects := []string{"bar", "baz", "foo", "quxx"}
	bktInfo, _ := createBucketAndObject(t, tc, bktName, objects[0])

	for _, objName := range objects[1:] {
		createTestObject(tc.Context(), t, tc, bktInfo, objName)
	}

	listV2Response1 := listObjectsV2(t, tc, bktName, "bar", "", 1)
	nextContinuationToken := listV2Response1.NextContinuationToken
	require.Equal(t, "baz", listV2Response1.Contents[0].Key)

	listV2Response2 := listObjectsV2(t, tc, bktName, "bar", nextContinuationToken, -1)

	require.Equal(t, nextContinuationToken, listV2Response2.ContinuationToken)
	require.Equal(t, "bar", listV2Response2.StartAfter)
	require.False(t, listV2Response2.IsTruncated)

	require.Equal(t, "foo", listV2Response2.Contents[0].Key)
	require.Equal(t, "quxx", listV2Response2.Contents[1].Key)
}

func listObjectsV2(t *testing.T, tc *handlerContext, bktName, startAfter, continuationToken string, maxKeys int) *ListObjectsV2Response {
	query := make(url.Values)
	if len(startAfter) != 0 {
		query.Add("start-after", startAfter)
	}
	if len(continuationToken) != 0 {
		query.Add("continuation-token", continuationToken)
	}
	if maxKeys != -1 {
		query.Add("max-keys", strconv.Itoa(maxKeys))
	}

	w, r := prepareTestFullRequest(t, bktName, "", query, nil)
	tc.Handler().ListObjectsV2Handler(w, r)
	assertStatus(t, w, http.StatusOK)
	res := &ListObjectsV2Response{}
	parseTestResponse(t, w, res)
	return res
}
