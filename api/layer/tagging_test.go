package layer

import (
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/stretchr/testify/require"
)

func TestPutObjectTaggingRemovesPreviousTagObjects(t *testing.T) {
	tc := prepareContext(t)
	obj := tc.putObject([]byte("content"))

	p := &PutObjectTaggingParams{
		ObjectVersion: &ObjectVersion{
			BktInfo:    tc.bktInfo,
			ObjectName: obj.Name,
		},
		TagSet: map[string]string{"key": "value1"},
	}

	// The version is unknown, so it is resolved during the tagging.
	require.NoError(t, tc.layer.PutObjectTagging(tc.ctx, p))
	require.NotEmpty(t, p.ObjectVersion.VersionID)
	require.Equal(t, 1, countTagObjects(tc.testNeoFS, p.ObjectVersion))

	p.TagSet = map[string]string{"key": "value2"}
	p.ObjectVersion.VersionID = ""

	require.NoError(t, tc.layer.PutObjectTagging(tc.ctx, p))
	require.Equal(t, 1, countTagObjects(tc.testNeoFS, p.ObjectVersion))

	// The same for an explicitly specified version.
	p.TagSet = map[string]string{"key": "value3"}

	require.NoError(t, tc.layer.PutObjectTagging(tc.ctx, p))
	require.Equal(t, 1, countTagObjects(tc.testNeoFS, p.ObjectVersion))
}

func countTagObjects(neoFS *TestNeoFS, p *ObjectVersion) int {
	var count int

	for _, obj := range neoFS.Objects() {
		var (
			isTag      bool
			associated string
		)
		for _, attr := range obj.Attributes() {
			switch attr.Key() {
			case s3headers.MetaType:
				isTag = attr.Value() == s3headers.TypeTags
			case object.AttributeAssociatedObject:
				associated = attr.Value()
			}
		}

		if isTag && associated == p.VersionID {
			count++
		}
	}

	return count
}
