package handler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/stretchr/testify/require"
)

func TestDeleteObject(t *testing.T) {
	ctx := context.Background()
	tc := prepareHandlerContext(t)

	bktName := "bucket-for-removal"
	createTestBucket(ctx, t, tc, bktName)
	bktInfo, err := tc.Layer().GetBucketInfo(ctx, bktName)
	require.NoError(t, err)

	objName := "object"
	objInfo := createTestObject(ctx, t, tc, bktInfo, objName)

	w, r := prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().DeleteObjectHandler(w, r)
	assertStatus(t, w, http.StatusNoContent)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotFound)

	p := &layer.GetObjectParams{
		BucketInfo: bktInfo,
		ObjectInfo: objInfo,
		Writer:     io.Discard,
	}

	err = tc.Layer().GetObject(ctx, p)
	require.Error(t, err)
}

func TestDeleteObjectVersioned(t *testing.T) {
	ctx := context.Background()
	tc := prepareHandlerContext(t)

	bktName := "bucket-for-removal"
	createTestBucket(ctx, t, tc, bktName)
	bktInfo, err := tc.Layer().GetBucketInfo(ctx, bktName)
	require.NoError(t, err)

	cfg := &VersioningConfiguration{Status: "Enabled"}
	w, r := prepareTestRequest(t, bktName, "", cfg)
	tc.Handler().PutBucketVersioningHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	objName := "object"
	objInfo := createTestObject(ctx, t, tc, bktInfo, objName)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().DeleteObjectHandler(w, r)
	assertStatus(t, w, http.StatusNoContent)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotFound)

	query := make(url.Values)
	query.Add(api.QueryVersionID, objInfo.Version())

	w, r = prepareTestFullRequest(t, bktName, objName, query, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestFullRequest(t, bktName, objName, query, nil)
	r.URL.RawQuery = query.Encode()
	tc.Handler().DeleteObjectHandler(w, r)
	assertStatus(t, w, http.StatusNoContent)

	p := &layer.GetObjectParams{
		BucketInfo: bktInfo,
		ObjectInfo: objInfo,
		Writer:     io.Discard,
	}
	err = tc.Layer().GetObject(ctx, p)
	require.Error(t, err)
}

func TestDeleteObjectCombined(t *testing.T) {
	ctx := context.Background()
	tc := prepareHandlerContext(t)

	bktName := "bucket-for-removal"
	createTestBucket(ctx, t, tc, bktName)
	bktInfo, err := tc.Layer().GetBucketInfo(ctx, bktName)
	require.NoError(t, err)

	objName := "object"
	objInfo := createTestObject(ctx, t, tc, bktInfo, objName)

	w, r := prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	cfg := &VersioningConfiguration{Status: "Enabled"}
	w, r = prepareTestRequest(t, bktName, objName, cfg)
	tc.Handler().PutBucketVersioningHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().DeleteObjectHandler(w, r)
	assertStatus(t, w, http.StatusNoContent)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotFound)

	query := make(url.Values)
	query.Add(api.QueryVersionID, objInfo.Version())

	w, r = prepareTestFullRequest(t, bktName, objName, query, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotFound) // because we remove null version

	p := &layer.GetObjectParams{
		BucketInfo: bktInfo,
		ObjectInfo: objInfo,
		Writer:     io.Discard,
	}
	err = tc.Layer().GetObject(ctx, p)
	require.Error(t, err)
}
