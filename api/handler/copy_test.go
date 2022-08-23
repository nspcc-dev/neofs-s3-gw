package handler

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/stretchr/testify/require"
)

type CopyMeta struct {
	TaggingDirective  string
	Tags              map[string]string
	MetadataDirective string
	Metadata          map[string]string
}

func TestCopyWithTaggingDirective(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-copy", "object-from-copy"
	objToCopy, objToCopy2 := "object-to-copy", "object-to-copy-2"
	createBucketAndObject(t, tc, bktName, objName)

	putObjectTagging(t, tc, bktName, objName, map[string]string{"key": "val"})

	copyMeta := CopyMeta{
		Tags: map[string]string{"key2": "val"},
	}
	copyObject(t, tc, bktName, objName, objToCopy, copyMeta)
	tagging := getObjectTagging(t, tc, bktName, objToCopy, emptyVersion)
	require.Len(t, tagging.TagSet, 1)
	require.Equal(t, "key", tagging.TagSet[0].Key)
	require.Equal(t, "val", tagging.TagSet[0].Value)

	copyMeta.TaggingDirective = replaceDirective
	copyObject(t, tc, bktName, objName, objToCopy2, copyMeta)
	tagging = getObjectTagging(t, tc, bktName, objToCopy2, emptyVersion)
	require.Len(t, tagging.TagSet, 1)
	require.Equal(t, "key2", tagging.TagSet[0].Key)
	require.Equal(t, "val", tagging.TagSet[0].Value)
}

func copyObject(t *testing.T, tc *handlerContext, bktName, fromObject, toObject string, copyMeta CopyMeta) {
	w, r := prepareTestRequest(t, bktName, toObject, nil)
	r.Header.Set(api.AmzCopySource, bktName+"/"+fromObject)

	r.Header.Set(api.AmzMetadataDirective, copyMeta.MetadataDirective)
	for key, val := range copyMeta.Metadata {
		r.Header.Set(api.MetadataPrefix+key, val)
	}

	r.Header.Set(api.AmzTaggingDirective, copyMeta.TaggingDirective)
	tagsQuery := make(url.Values)
	for key, val := range copyMeta.Tags {
		tagsQuery.Set(key, val)
	}
	r.Header.Set(api.AmzTagging, tagsQuery.Encode())

	tc.Handler().CopyObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)
}

func putObjectTagging(t *testing.T, tc *handlerContext, bktName, objName string, tags map[string]string) {
	body := &Tagging{
		TagSet: make([]Tag, 0, len(tags)),
	}

	for key, val := range tags {
		body.TagSet = append(body.TagSet, Tag{
			Key:   key,
			Value: val,
		})
	}

	w, r := prepareTestRequest(t, bktName, objName, body)
	tc.Handler().PutObjectTaggingHandler(w, r)
	assertStatus(t, w, http.StatusOK)
}

func getObjectTagging(t *testing.T, tc *handlerContext, bktName, objName, version string) *Tagging {
	query := make(url.Values)
	query.Add(api.QueryVersionID, version)

	w, r := prepareTestFullRequest(t, bktName, objName, query, nil)
	tc.Handler().GetObjectTaggingHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	tagging := &Tagging{}
	err := xml.NewDecoder(w.Result().Body).Decode(tagging)
	require.NoError(t, err)
	return tagging
}
