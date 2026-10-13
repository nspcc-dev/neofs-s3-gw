package handler

import (
	"encoding/xml"
	"net/http"
	"net/url"
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
