package handler

import (
	"bytes"
	"cmp"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
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
