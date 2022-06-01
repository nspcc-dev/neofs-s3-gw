package handler

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/stretchr/testify/require"
)

func TestConditionalHead(t *testing.T) {
	ctx := context.Background()
	tc := prepareHandlerContext(t)

	bktName := "bucket-for-conditional"
	createTestBucket(ctx, t, tc, bktName)
	bktInfo, err := tc.Layer().GetBucketInfo(ctx, bktName)
	require.NoError(t, err)

	objName := "object"
	createTestObject(ctx, t, tc, bktInfo, objName)

	w, r := prepareTestRequest(t, bktName, objName, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	etag := w.Result().Header.Get(api.ETag)
	lastModified := w.Result().Header.Get(api.LastModified)
	_ = lastModified

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfMatch, etag)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfMatch, "etag")
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusPreconditionFailed)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfUnmodifiedSince, time.Now().UTC().Format(http.TimeFormat))
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	var zeroTime time.Time
	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfUnmodifiedSince, zeroTime.UTC().Format(http.TimeFormat))
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusPreconditionFailed)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfMatch, etag)
	r.Header.Set(api.IfUnmodifiedSince, zeroTime.UTC().Format(http.TimeFormat))
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfNoneMatch, etag)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotModified)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfNoneMatch, "etag")
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfModifiedSince, zeroTime.UTC().Format(http.TimeFormat))
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfModifiedSince, time.Now().Add(time.Minute).UTC().Format(http.TimeFormat))
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotModified)

	w, r = prepareTestRequest(t, bktName, objName, nil)
	r.Header.Set(api.IfNoneMatch, etag)
	r.Header.Set(api.IfModifiedSince, zeroTime.UTC().Format(http.TimeFormat))
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotModified)
}
