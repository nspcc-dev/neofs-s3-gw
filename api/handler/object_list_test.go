package handler

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
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
	require.Equal(t, layer.UnversionedObjectVersionID, result.Version[1].VersionID)
}
