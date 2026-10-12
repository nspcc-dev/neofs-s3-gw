package layer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/stretchr/testify/require"
)

func TestTrimAfterUploadIDAndKey(t *testing.T) {
	uploads := []*UploadInfo{
		{Key: "j", UploadID: "k"}, // key < id <
		{Key: "l", UploadID: "p"}, // key < id >
		{Key: "n", UploadID: "m"}, // key = id <
		{Key: "n", UploadID: "o"}, // pivot
		{Key: "n", UploadID: "q"}, // key = id >
		{Key: "p", UploadID: "h"}, // key > id <
		{Key: "q", UploadID: "r"}, // key > id >
	}
	expectedUploadsListsIndexes := [][]int{
		{1, 2, 3, 4, 6},
		{4, 6},
		{3, 4, 6},
		{4, 6},
		{6},
		{6},
		{},
	}

	slices.SortFunc(uploads, func(a, b *UploadInfo) int {
		if compare := cmp.Compare(a.Key, b.Key); compare != 0 {
			return compare
		}

		return cmp.Compare(a.UploadID, b.UploadID)
	})

	length := len(uploads)

	t.Run("the last element's key is less, upload id is less", func(t *testing.T) {
		keys := trimAfterUploadIDAndKey("z", "a", uploads)
		require.Empty(t, keys)
		require.Len(t, uploads, length)
	})

	t.Run("the last element's key is less, upload id is greater", func(t *testing.T) {
		keys := trimAfterUploadIDAndKey("z", "a", uploads)
		require.Empty(t, keys)
		require.Len(t, uploads, length)
	})

	t.Run("check for uploads", func(t *testing.T) {
		for i, u := range uploads {
			list := trimAfterUploadIDAndKey(u.Key, u.UploadID, uploads)
			require.Equal(t, len(list), len(expectedUploadsListsIndexes[i]))
			for j, idx := range expectedUploadsListsIndexes[i] {
				require.Equal(t, list[j], uploads[idx])
			}
		}
	})
}

func TestTrimAfterUploadKey(t *testing.T) {
	var (
		uploadKeys    = []string{"e", "f", "f", "g", "h", "i"}
		theSameKeyIdx = []int{1, 2}
		diffKeyIdx    = []int{0, 3}
		lastIdx       = len(uploadKeys) - 1
	)

	uploadsInfos := make([]*UploadInfo, 0, len(uploadKeys))
	for _, k := range uploadKeys {
		uploadsInfos = append(uploadsInfos, &UploadInfo{Key: k})
	}

	t.Run("empty list", func(t *testing.T) {
		keys := trimAfterUploadKey("f", []*UploadInfo{})
		require.Len(t, keys, 0)
	})

	t.Run("the last element is less than a key", func(t *testing.T) {
		keys := trimAfterUploadKey("j", uploadsInfos)
		require.Empty(t, keys)
		require.Len(t, uploadsInfos, len(uploadKeys))
	})

	t.Run("different keys in sequence", func(t *testing.T) {
		for _, i := range diffKeyIdx {
			keys := trimAfterUploadKey(uploadKeys[i], uploadsInfos)
			require.Len(t, keys, len(uploadKeys)-i-1)
			require.Equal(t, keys, uploadsInfos[i+1:])
			require.Len(t, uploadsInfos, len(uploadKeys))
		}
	})

	t.Run("the same keys in the sequence first element", func(t *testing.T) {
		for _, i := range theSameKeyIdx {
			keys := trimAfterUploadKey(uploadKeys[i], uploadsInfos)
			require.Len(t, keys, 3)
			require.Equal(t, keys, uploadsInfos[3:])
			require.Len(t, uploadsInfos, len(uploadKeys))
		}
	})

	t.Run("last element", func(t *testing.T) {
		keys := trimAfterUploadKey(uploadKeys[lastIdx], uploadsInfos)
		require.Empty(t, keys)
	})
}

func TestPrepareMultipartHeadObjectUniqueID(t *testing.T) {
	tc := prepareContext(t)
	ctx := context.WithValue(tc.ctx, api.ClientTime, time.Now())

	prepare := func() oid.ID {
		header, err := tc.layer.(*layer).prepareMultipartHeadObject(ctx, multipartHeadObjectParams{
			PutObject: PutObjectParams{
				BktInfo: tc.bktInfo,
				Reader:  bytes.NewBuffer(nil),
				Header:  map[string]string{s3headers.MultipartPartNumber: "1"},
			},
			PayloadHash: sha256.New(),
		})
		require.NoError(t, err)
		return header.GetID()
	}

	// The same part uploaded again at the same time must not get the ID of the previous one, it may be removed already.
	require.NotEqual(t, prepare(), prepare())
}
