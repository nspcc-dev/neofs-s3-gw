package handler

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/stretchr/testify/require"
)

func TestGetObjectPartsAttributes(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName := "bucket-get-attributes"
	objName, objMultipartName := "object", "object-multipart"

	createTestBucket(hc, bktName)

	body := bytes.NewReader([]byte("content"))
	w, r := prepareTestPayloadRequest(hc, bktName, objName, body)
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(hc, bktName, objName, nil)
	r.Header.Set(api.AmzObjectAttributes, objectParts)
	hc.Handler().GetObjectAttributesHandler(w, r)
	result := &GetObjectAttributesResponse{}
	parseTestResponse(t, w, result)
	require.Nil(t, result.ObjectParts)

	w, r = prepareTestRequest(hc, bktName, objMultipartName, nil)
	hc.Handler().CreateMultipartUploadHandler(w, r)
	multipartUpload := &InitiateMultipartUploadResponse{}
	parseTestResponse(t, w, multipartUpload)

	body2 := bytes.NewReader([]byte("content2"))
	w, r = prepareTestPayloadRequest(hc, bktName, objMultipartName, body2)
	query := make(url.Values)
	query.Add(uploadIDHeaderName, multipartUpload.UploadID)
	query.Add(partNumberHeaderName, "1")
	r.URL.RawQuery = query.Encode()
	hc.Handler().UploadPartHandler(w, r)
	assertStatus(t, w, http.StatusOK)
	etag := w.Result().Header.Get(api.ETag)

	completeUpload := &CompleteMultipartUpload{
		Parts: []*layer.CompletedPart{{
			ETag:       etag,
			PartNumber: 1,
		}},
	}
	w, r = prepareTestRequest(hc, bktName, objMultipartName, completeUpload)
	query = make(url.Values)
	query.Add(uploadIDHeaderName, multipartUpload.UploadID)
	r.URL.RawQuery = query.Encode()
	hc.Handler().CompleteMultipartUploadHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	w, r = prepareTestRequest(hc, bktName, objMultipartName, nil)
	r.Header.Set(api.AmzObjectAttributes, objectParts)
	hc.Handler().GetObjectAttributesHandler(w, r)
	result = &GetObjectAttributesResponse{}
	parseTestResponse(t, w, result)
	require.NotNil(t, result.ObjectParts)
	require.Len(t, result.ObjectParts.Parts, 1)
	require.Equal(t, etag, result.ObjectParts.Parts[0].ChecksumSHA256)
	require.Equal(t, 8, result.ObjectParts.Parts[0].Size)
	require.Equal(t, 1, result.ObjectParts.PartsCount)
}
