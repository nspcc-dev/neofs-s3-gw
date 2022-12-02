package handler

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/stretchr/testify/require"
)

func TestSimpleVersioning(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName, objName := "bkt-name", "obj-name"

	createTestBucket(hc, bktName)
	putBucketVersioning(t, hc, bktName, true)

	obj1Content1 := "content obj1 v1"
	version1, _ := putObjectContent(hc, bktName, objName, obj1Content1)

	obj1Content2 := "content obj1 v2"
	version2, etag2 := putObjectContent(hc, bktName, objName, obj1Content2)

	buffer2 := getObject(hc, bktName, objName, "")
	require.Equal(t, []byte(obj1Content2), buffer2)

	buffer1 := getObject(hc, bktName, objName, version1)
	require.Equal(t, []byte(obj1Content1), buffer1)

	checkLastObject(hc, bktName, objName, version2, etag2)
}

func TestSimpleNoVersioning(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName, objName := "bkt-name", "obj-name"
	createTestBucket(hc, bktName)

	obj1Content1 := "content obj1 v1"
	version1, _ := putObjectContent(hc, bktName, objName, obj1Content1)

	obj1Content2 := "content obj1 v2"
	version2, etag2 := putObjectContent(hc, bktName, objName, obj1Content2)

	buffer2 := getObject(hc, bktName, objName, "")
	require.Equal(t, []byte(obj1Content2), buffer2)

	checkNotFound(hc.t, hc, bktName, objName, version1)
	checkLastObject(hc, bktName, objName, version2, etag2)
}

func TestGetUnversioned(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName, objName := "bkt-name", "obj-name"

	createTestBucket(hc, bktName)

	objContent := "content obj1 v1"
	putObjectContent(hc, bktName, objName, objContent)

	putBucketVersioning(hc.t, hc, bktName, true)

	buffer := getObject(hc, bktName, objName, data.UnversionedObjectVersionID)
	require.Equal(t, objContent, string(buffer))
}

func TestVersioningDeleteSpecificObjectVersion(t *testing.T) {
	hc := prepareHandlerContext(t)
	bktName, objName := "bkt-name", "obj-name"

	createTestBucket(hc, bktName)
	putBucketVersioning(t, hc, bktName, true)

	putObjectContent(hc, bktName, objName, "content obj1 v1")
	version2, _ := putObjectContent(hc, bktName, objName, "content obj1 v2")
	objV3Content := "content obj1 v3"
	putObjectContent(hc, bktName, objName, objV3Content)

	deleteObject(t, hc, bktName, objName, version2)
	checkNotFound(t, hc, bktName, objName, version2)

	buffer3 := getObject(hc, bktName, objName, "")
	require.Equal(t, []byte(objV3Content), buffer3)

	deleteObject(t, hc, bktName, objName, "")
	checkNotFound(t, hc, bktName, objName, "")

	versions := listVersions(t, hc, bktName)
	for _, ver := range versions.DeleteMarker {
		if ver.IsLatest {
			deleteObject(t, hc, bktName, objName, ver.VersionID)
		}
	}
	buffer3 = getObject(hc, bktName, objName, "")
	require.Equal(t, []byte(objV3Content), buffer3)
}

func getObject(hc *handlerContext, bktName, objName, versionID string) []byte {
	query := make(url.Values)
	query.Add(api.QueryVersionID, versionID)

	w, r := prepareTestFullRequest(hc, bktName, objName, query, nil)
	hc.Handler().GetObjectHandler(w, r)
	assertStatus(hc.t, w, http.StatusOK)

	respData, err := io.ReadAll(w.Body)
	require.NoError(hc.t, err)

	return respData
}

func checkLastObject(hc *handlerContext, bktName, objName, versionID, etag string) {
	respV1 := listObjectsV1(hc.t, hc, bktName, "", "", "", -1)
	existed := false
	for _, obj := range respV1.Contents {
		if obj.Key == objName {
			existed = true
			require.Equal(hc.t, etag, obj.ETag)
		}
	}
	require.True(hc.t, existed)

	respV2 := listObjectsV2(hc.t, hc, bktName, "", "", "", "", -1)
	existed = false
	for _, obj := range respV2.Contents {
		if obj.Key == objName {
			existed = true
			require.Equal(hc.t, etag, obj.ETag)
		}
	}
	require.True(hc.t, existed)

	versions := listVersions(hc.t, hc, bktName)
	existed = false
	for _, obj := range versions.Version {
		if obj.Key == objName && obj.IsLatest {
			existed = true
			require.Equal(hc.t, etag, obj.ETag)
			require.Equal(hc.t, versionID, obj.VersionID)
		}
	}
	require.True(hc.t, existed)
}
