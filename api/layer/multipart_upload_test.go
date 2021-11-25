package layer

import (
	"sort"
	"testing"

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

	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key == uploads[j].Key {
			return uploads[i].UploadID < uploads[j].UploadID
		}
		return uploads[i].Key < uploads[j].Key
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
