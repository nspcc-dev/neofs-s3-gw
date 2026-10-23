package handler

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/stretchr/testify/require"
)

func TestCompleteMultipartUploadRepeat(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-repeat-complete", "object-multipart"
	createTestBucket(hc, bktName)

	multipartInfo := createMultipartUpload(hc, bktName, objName, map[string]string{})
	etag1, _ := uploadPart(hc, bktName, objName, multipartInfo.UploadID, 1, 5*1048576)
	etag2, _ := uploadPart(hc, bktName, objName, multipartInfo.UploadID, 2, 10)

	query := make(url.Values)
	query.Set(uploadIDQuery, multipartInfo.UploadID)
	complete := &CompleteMultipartUpload{
		Parts: []*layer.CompletedPart{
			{ETag: etag1, PartNumber: 1},
			{ETag: etag2, PartNumber: 2},
		},
	}

	completeAndGetETag := func() string {
		w, r := prepareTestFullRequest(hc, bktName, objName, query, complete)
		hc.Handler().CompleteMultipartUploadHandler(w, r)
		assertStatus(t, w, http.StatusOK)

		var resp CompleteMultipartUploadResponse
		require.NoError(t, xml.NewDecoder(w.Result().Body).Decode(&resp))
		require.Equal(t, objName, resp.Key)
		return resp.ETag
	}

	etag := completeAndGetETag()
	require.Equal(t, etag, completeAndGetETag())

	t.Run("other parts", func(t *testing.T) {
		for _, parts := range [][]*layer.CompletedPart{
			{{ETag: etag1, PartNumber: 1}},
			{{ETag: etag2, PartNumber: 2}},
			{{ETag: etag1, PartNumber: 1}, {ETag: etag1, PartNumber: 2}},
		} {
			w, r := prepareTestFullRequest(hc, bktName, objName, query, &CompleteMultipartUpload{Parts: parts})
			hc.Handler().CompleteMultipartUploadHandler(w, r)
			assertS3Error(t, w, s3errors.GetAPIError(s3errors.ErrInvalidPart))
		}
	})

	t.Run("other key", func(t *testing.T) {
		w, r := prepareTestFullRequest(hc, bktName, "other-object", query, complete)
		hc.Handler().CompleteMultipartUploadHandler(w, r)
		assertS3Error(t, w, s3errors.GetAPIError(s3errors.ErrNoSuchUpload))
	})
}

func TestCompleteMultipartUploadPartsSubset(t *testing.T) {
	const partSize = 5 * 1048576

	hc := prepareHandlerContext(t)

	bktName := "bucket-for-parts-subset"
	createTestBucket(hc, bktName)

	for _, tc := range []struct {
		name      string
		uploaded  []int
		completed []int
	}{
		{name: "gaps", uploaded: []int{1, 5, 14}, completed: []int{1, 5, 14}},
		{name: "subset", uploaded: []int{1, 2, 3, 4, 5}, completed: []int{1, 3, 5}},
		{name: "out of order upload", uploaded: []int{3, 1, 2}, completed: []int{1, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objName := "object-" + tc.name
			multipartInfo := createMultipartUpload(hc, bktName, objName, map[string]string{})

			etags := make(map[int]string, len(tc.uploaded))
			payloads := make(map[int][]byte, len(tc.uploaded))
			for _, num := range tc.uploaded {
				etags[num], payloads[num] = uploadPart(hc, bktName, objName, multipartInfo.UploadID, num, partSize+num)
			}

			var (
				complete CompleteMultipartUpload
				expected []byte
			)
			for _, num := range tc.completed {
				complete.Parts = append(complete.Parts, &layer.CompletedPart{ETag: etags[num], PartNumber: num})
				expected = slices.Concat(expected, payloads[num])
			}

			query := make(url.Values)
			query.Set(uploadIDQuery, multipartInfo.UploadID)
			w, r := prepareTestFullRequest(hc, bktName, objName, query, &complete)
			hc.Handler().CompleteMultipartUploadHandler(w, r)
			assertStatus(t, w, http.StatusOK)

			require.Equal(t, expected, getObjectRange(t, hc, bktName, objName, 0, len(expected)-1))
		})
	}
}
