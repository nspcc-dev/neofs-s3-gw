package layer

import (
	"context"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
)

type orderedSearchNeoFS struct {
	*TestNeoFS
	items []client.SearchResultItem
}

func (n *orderedSearchNeoFS) SearchObjectsV2(context.Context, cid.ID, object.SearchFilters, []string, client.SearchObjectsOptions) ([]client.SearchResultItem, error) {
	return n.items, nil
}

func TestComprehensiveSearchAllVersionsSkipsTags(t *testing.T) {
	var (
		objectID   = oidtest.ID()
		oldTagID   = oidtest.ID()
		newTagID   = oidtest.ID()
		attributes = []string{
			object.AttributeFilePath,
			object.AttributeTimestamp,
			s3headers.AttributeVersioningState,
			s3headers.AttributeDeleteMarker,
			s3headers.MetaType,
			object.AttributeAssociatedObject,
			s3headers.AttributeLockMeta,
		}
	)

	item := func(itemID oid.ID, timestamp, metaType string) client.SearchResultItem {
		attrs := make([]string, len(attributes))
		attrs[0] = "obj1"
		attrs[1] = timestamp
		attrs[4] = metaType
		if metaType == s3headers.TypeTags {
			attrs[5] = objectID.EncodeToString()
		}
		return client.SearchResultItem{ID: itemID, Attributes: attrs}
	}

	// The newer tag object is returned before the older one. The older one must
	// not be treated as another version of the object.
	neoFS := &orderedSearchNeoFS{
		TestNeoFS: &TestNeoFS{},
		items: []client.SearchResultItem{
			item(objectID, "100", ""),
			item(newTagID, "201", s3headers.TypeTags),
			item(oldTagID, "200", s3headers.TypeTags),
		},
	}

	l := &layer{neoFS: neoFS}
	results, tagsObjectID, _, err := l.comprehensiveSearchAllVersionsInNeoFS(context.Background(), &data.BucketInfo{}, "obj1")
	require.NoError(t, err)
	require.Equal(t, newTagID, tagsObjectID)
	require.Len(t, results, 1)
	require.Equal(t, objectID, results[0].ID)
	require.Equal(t, "obj1", results[0].FilePath)
}

func TestExtractFilePath(t *testing.T) {
	for _, filePath := range []string{"asdf", "_obj1_", "boo/bar", ""} {
		t.Run(filePath, func(t *testing.T) {
			res, err := extractFilePath(generateContinuationToken(filePath))
			require.NoError(t, err)
			require.Equal(t, filePath, res)

			res, err = extractFilePath(generateAdjustedContinuationToken(filePath, oidtest.ID()))
			require.NoError(t, err)
			require.Equal(t, filePath, res)
		})
	}

	_, err := extractFilePath("")
	require.Error(t, err)
}
