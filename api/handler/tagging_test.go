package handler

import (
	"bytes"
	"cmp"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
)

func TestTagsValidity(t *testing.T) {
	sbKey := strings.Builder{}
	for range keyTagMaxLength {
		sbKey.WriteByte('a')
	}
	sbValue := strings.Builder{}
	for range valueTagMaxLength {
		sbValue.WriteByte('a')
	}

	for _, tc := range []struct {
		tag   Tag
		valid bool
	}{
		{tag: Tag{}, valid: false},
		{tag: Tag{Key: "", Value: "1"}, valid: false},
		{tag: Tag{Key: "aws:key", Value: "val"}, valid: false},
		{tag: Tag{Key: "key~", Value: "val"}, valid: false},
		{tag: Tag{Key: "key\\", Value: "val"}, valid: false},
		{tag: Tag{Key: "key?", Value: "val"}, valid: false},
		{tag: Tag{Key: sbKey.String() + "b", Value: "val"}, valid: false},
		{tag: Tag{Key: "key", Value: sbValue.String() + "b"}, valid: false},

		{tag: Tag{Key: sbKey.String(), Value: "val"}, valid: true},
		{tag: Tag{Key: "key", Value: sbValue.String()}, valid: true},
		{tag: Tag{Key: "k e y", Value: "v a l"}, valid: true},
		{tag: Tag{Key: "12345", Value: "1234"}, valid: true},
		{tag: Tag{Key: allowedTagChars, Value: allowedTagChars}, valid: true},
	} {
		err := checkTag(tc.tag)
		if tc.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

func TestEmptyTagValue(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-empty-tag-value", "object"
	createTestBucket(hc, bktName)

	expected := []Tag{{Key: "bar", Value: ""}, {Key: "foo", Value: "bar"}}

	w, r := prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte("content")))
	r.Header.Set(api.AmzTagging, "foo=bar&bar")
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	tagging := getObjectTagging(t, hc, bktName, objName, "")
	slices.SortFunc(tagging.TagSet, func(a, b Tag) int { return cmp.Compare(a.Key, b.Key) })
	require.Equal(t, expected, tagging.TagSet)

	putObjectTagging(t, hc, bktName, objName, map[string]string{"bar": "", "foo": "bar"})

	tagging = getObjectTagging(t, hc, bktName, objName, "")
	slices.SortFunc(tagging.TagSet, func(a, b Tag) int { return cmp.Compare(a.Key, b.Key) })
	require.Equal(t, expected, tagging.TagSet)
}

func TestDeleteObjectTaggingInlineTags(t *testing.T) {
	hc := prepareHandlerContext(t)
	enableNamesCache(hc)

	bktName, objName := "bucket-inline-tags", "object"
	createTestBucket(hc, bktName)

	w, r := prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte("content")))
	r.Header.Set(api.AmzTagging, "foo=bar&baz=qux")
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)
	require.Len(t, getObjectTagging(t, hc, bktName, objName, "").TagSet, 2)

	deleteObjectTagging(t, hc, bktName, objName)
	require.Empty(t, getObjectTagging(t, hc, bktName, objName, "").TagSet)
	requireTaggingCount(t, hc, bktName, objName, "0")

	putObjectTagging(t, hc, bktName, objName, map[string]string{"k": "v"})
	requireTaggingCount(t, hc, bktName, objName, "1")

	putObjectTagging(t, hc, bktName, objName, nil)
	requireTaggingCount(t, hc, bktName, objName, "0")

	// An object without inline tags.
	objName = "object-no-inline-tags"
	w, r = prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte("content")))
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	putObjectTagging(t, hc, bktName, objName, map[string]string{"k": "v"})
	deleteObjectTagging(t, hc, bktName, objName)
	require.Empty(t, getObjectTagging(t, hc, bktName, objName, "").TagSet)
}

// requireTaggingCount checks x-amz-tagging-count of HeadObject and GetObject,
// with and without the name cache.
func requireTaggingCount(t *testing.T, hc *handlerContext, bktName, objName, expected string) {
	for range 2 {
		w, r := prepareTestRequest(hc, bktName, objName, nil)
		hc.Handler().HeadObjectHandler(w, r)
		assertStatus(t, w, http.StatusOK)
		require.Equal(t, expected, w.Header().Get(api.AmzTaggingCount))

		w, r = prepareTestRequest(hc, bktName, objName, nil)
		hc.Handler().GetObjectHandler(w, r)
		assertStatus(t, w, http.StatusOK)
		require.Equal(t, expected, w.Header().Get(api.AmzTaggingCount))
	}
}

func deleteObjectTagging(t *testing.T, hc *handlerContext, bktName, objName string) {
	w, r := prepareTestRequest(hc, bktName, objName, nil)
	hc.Handler().DeleteObjectTaggingHandler(w, r)
	assertStatus(t, w, http.StatusNoContent)
}

func TestDeleteObjectTaggingVersion(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-tagging-version", "object"
	bktInfo := createTestBucket(hc, bktName)

	w, r := prepareTestPayloadRequest(hc, bktName, objName, bytes.NewReader([]byte("content")))
	r.Header.Set(api.AmzTagging, "foo=bar")
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	id, err := hc.Layer().GetIDForVersioningContainer(hc.Context(), &layer.ShortInfoParams{
		Owner:           bktInfo.Owner,
		CID:             bktInfo.CID,
		Object:          objName,
		FindNullVersion: true,
	})
	require.NoError(t, err)

	deleteVersion := func(objName, version string) *httptest.ResponseRecorder {
		query := make(url.Values)
		query.Add(api.QueryVersionID, version)

		w, r := prepareTestFullRequest(hc, bktName, objName, query, nil)
		hc.Handler().DeleteObjectTaggingHandler(w, r)
		return w
	}

	assertStatus(t, deleteVersion(objName, data.UnversionedObjectVersionID), http.StatusNoContent)

	noSuchVersion := s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
	assertS3Error(t, deleteVersion(objName, "invalid"), noSuchVersion)
	assertS3Error(t, deleteVersion(objName, oidtest.ID().EncodeToString()), noSuchVersion)
	// The version of another object.
	assertS3Error(t, deleteVersion("another-object", id.EncodeToString()), noSuchVersion)
	require.Len(t, getObjectTagging(t, hc, bktName, objName, "").TagSet, 1)

	assertStatus(t, deleteVersion(objName, id.EncodeToString()), http.StatusNoContent)
	require.Empty(t, getObjectTagging(t, hc, bktName, objName, "").TagSet)
}
