package handler

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/stretchr/testify/require"
)

const (
	emptyVersion = ""
)

func TestDeleteObject(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	bktInfo, objInfo := createBucketAndObject(t, tc, bktName, objName)

	checkFound(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	require.False(t, existInMockedNeoFS(tc, bktInfo, objInfo))
}

func TestDeleteObjectVersioned(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	bktInfo, objInfo := createVersionedBucketAndObject(t, tc, bktName, objName)

	checkFound(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	checkFound(t, tc, bktName, objName, objInfo.Version())
	deleteObject(t, tc, bktName, objName, objInfo.Version())
	checkNotFound(t, tc, bktName, objName, objInfo.Version())

	require.False(t, existInMockedNeoFS(tc, bktInfo, objInfo), "object exists but shouldn't")
}

func TestDeleteObjectUnversioned(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal-unversioned", "object-to-delete-unversioned"
	bktInfo, objInfo := createBucketAndObject(t, tc, bktName, objName)

	checkFound(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	versions := listVersions(t, tc, bktName)
	require.Len(t, versions.DeleteMarker, 0, "delete markers must be empty")
	require.Len(t, versions.Version, 0, "versions must be empty")

	require.False(t, existInMockedNeoFS(tc, bktInfo, objInfo), "object exists but shouldn't")
}

func TestRemoveDeleteMarker(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	bktInfo, objInfo := createVersionedBucketAndObject(t, tc, bktName, objName)

	checkFound(t, tc, bktName, objName, emptyVersion)
	deleteMarkerVersion := deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	checkFound(t, tc, bktName, objName, objInfo.Version())
	deleteObject(t, tc, bktName, objName, deleteMarkerVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	require.True(t, existInMockedNeoFS(tc, bktInfo, objInfo), "object doesn't exist but should")
}

func TestDeleteObjectCombined(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	bktInfo, objInfo := createBucketAndObject(t, tc, bktName, objName)

	putBucketVersioning(t, tc, bktName, true)

	checkFound(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	checkFound(t, tc, bktName, objName, objInfo.Version())

	require.True(t, existInMockedNeoFS(tc, bktInfo, objInfo), "object doesn't exist but should")
}

func TestDeleteObjectSuspended(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	bktInfo, objInfo := createBucketAndObject(t, tc, bktName, objName)

	putBucketVersioning(t, tc, bktName, true)

	checkFound(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, emptyVersion)

	putBucketVersioning(t, tc, bktName, false)

	deleteObject(t, tc, bktName, objName, emptyVersion)
	checkNotFound(t, tc, bktName, objName, objInfo.Version())

	require.False(t, existInMockedNeoFS(tc, bktInfo, objInfo), "object exists but shouldn't")
}

func TestDeleteMarkers(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	createTestBucket(tc.Context(), t, tc, bktName)
	putBucketVersioning(t, tc, bktName, true)

	checkNotFound(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)
	deleteObject(t, tc, bktName, objName, emptyVersion)

	versions := listVersions(t, tc, bktName)
	require.Len(t, versions.DeleteMarker, 3, "invalid delete markers length")
	require.Len(t, versions.Version, 0, "versions must be empty")

	require.Len(t, listOIDsFromMockedNeoFS(t, tc, bktName, objName), 0, "shouldn't be any object in neofs")
}

func TestDeleteObjectFromListCache(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-removal", "object-to-delete"
	bktInfo, objInfo := createVersionedBucketAndObject(t, tc, bktName, objName)

	versions := listObjectsV1(t, tc, bktName)
	require.Len(t, versions.Contents, 1)

	checkFound(t, tc, bktName, objName, objInfo.Version())
	deleteObject(t, tc, bktName, objName, objInfo.Version())
	checkNotFound(t, tc, bktName, objName, objInfo.Version())

	// check cache is clean after object removal
	versions = listObjectsV1(t, tc, bktName)
	require.Len(t, versions.Contents, 0)

	require.False(t, existInMockedNeoFS(tc, bktInfo, objInfo))
}

func createBucketAndObject(t *testing.T, tc *handlerContext, bktName, objName string) (*data.BucketInfo, *data.ObjectInfo) {
	createTestBucket(tc.Context(), t, tc, bktName)
	bktInfo, err := tc.Layer().GetBucketInfo(tc.Context(), bktName)
	require.NoError(t, err)

	objInfo := createTestObject(tc.Context(), t, tc, bktInfo, objName)

	return bktInfo, objInfo
}

func createVersionedBucketAndObject(t *testing.T, tc *handlerContext, bktName, objName string) (*data.BucketInfo, *data.ObjectInfo) {
	createTestBucket(tc.Context(), t, tc, bktName)
	bktInfo, err := tc.Layer().GetBucketInfo(tc.Context(), bktName)
	require.NoError(t, err)
	putBucketVersioning(t, tc, bktName, true)

	objInfo := createTestObject(tc.Context(), t, tc, bktInfo, objName)

	return bktInfo, objInfo
}

func putBucketVersioning(t *testing.T, tc *handlerContext, bktName string, enabled bool) {
	cfg := &VersioningConfiguration{Status: "Suspended"}
	if enabled {
		cfg.Status = "Enabled"
	}
	w, r := prepareTestRequest(t, bktName, "", cfg)
	tc.Handler().PutBucketVersioningHandler(w, r)
	assertStatus(t, w, http.StatusOK)
}

func deleteObject(t *testing.T, tc *handlerContext, bktName, objName, version string) string {
	query := make(url.Values)
	query.Add(api.QueryVersionID, version)

	w, r := prepareTestFullRequest(t, bktName, objName, query, nil)
	tc.Handler().DeleteObjectHandler(w, r)
	assertStatus(t, w, http.StatusNoContent)

	return w.Header().Get(api.AmzVersionID)
}

func checkNotFound(t *testing.T, tc *handlerContext, bktName, objName, version string) {
	query := make(url.Values)
	query.Add(api.QueryVersionID, version)

	w, r := prepareTestFullRequest(t, bktName, objName, query, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusNotFound)
}

func checkFound(t *testing.T, tc *handlerContext, bktName, objName, version string) {
	query := make(url.Values)
	query.Add(api.QueryVersionID, version)

	w, r := prepareTestFullRequest(t, bktName, objName, query, nil)
	tc.Handler().HeadObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)
}

func listVersions(t *testing.T, tc *handlerContext, bktName string) *ListObjectsVersionsResponse {
	w, r := prepareTestRequest(t, bktName, "", nil)
	tc.Handler().ListBucketObjectVersionsHandler(w, r)
	assertStatus(t, w, http.StatusOK)
	res := &ListObjectsVersionsResponse{}
	parseTestResponse(t, w, res)
	return res
}

func listObjectsV1(t *testing.T, tc *handlerContext, bktName string) *ListObjectsV1Response {
	w, r := prepareTestRequest(t, bktName, "", nil)
	tc.Handler().ListObjectsV1Handler(w, r)
	assertStatus(t, w, http.StatusOK)
	res := &ListObjectsV1Response{}
	parseTestResponse(t, w, res)
	return res
}
