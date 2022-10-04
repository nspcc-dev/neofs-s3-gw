package handler

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/stretchr/testify/require"
)

const (
	aes256Key       = "MTIzNDU2Nzg5MHF3ZXJ0eXVpb3Bhc2RmZ2hqa2x6eGM="
	aes256KeyMD5    = "NtkH/y2maPit+yUkhq4Q7A=="
	partNumberQuery = "partNumber"
	uploadIDQuery   = "uploadId"
)

func TestSimpleGetEncrypted(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-sse-c", "object-to-encrypt"
	bktInfo := createTestBucket(tc, bktName)

	content := "content"
	putEncryptedObject(t, tc, bktName, objName, content)

	objInfo, err := tc.Layer().GetObjectInfo(tc.Context(), &layer.HeadObjectParams{BktInfo: bktInfo, Object: objName})
	require.NoError(t, err)
	obj, err := tc.MockedPool().ReadObject(tc.Context(), layer.PrmObjectRead{Container: bktInfo.CID, Object: objInfo.ID})
	require.NoError(t, err)
	encryptedContent, err := io.ReadAll(obj.Payload)
	require.NoError(t, err)
	require.NotEqual(t, content, string(encryptedContent))

	response, _ := getEncryptedObject(t, tc, bktName, objName)
	require.Equal(t, content, string(response))
}

func TestGetEncryptedRange(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-sse-c", "object-to-encrypt"
	createTestBucket(tc, bktName)

	var sb strings.Builder
	for i := 0; i < 1<<16+11; i++ {
		switch i {
		case 0:
			sb.Write([]byte("b"))
		case 1<<16 - 2:
			sb.Write([]byte("c"))
		case 1<<16 - 1:
			sb.Write([]byte("d"))
		case 1 << 16:
			sb.Write([]byte("e"))
		case 1<<16 + 1:
			sb.Write([]byte("f"))
		case 1<<16 + 10:
			sb.Write([]byte("g"))
		default:
			sb.Write([]byte("a"))
		}
	}

	content := sb.String()
	putEncryptedObject(t, tc, bktName, objName, content)

	full := getEncryptedObjectRange(t, tc, bktName, objName, 0, sb.Len()-1)
	require.Equalf(t, content, string(full), "expected len: %d, actual len: %d", len(content), len(full))

	beginning := getEncryptedObjectRange(t, tc, bktName, objName, 0, 3)
	require.Equal(t, content[:4], string(beginning))

	middle := getEncryptedObjectRange(t, tc, bktName, objName, 1<<16-3, 1<<16+2)
	require.Equal(t, "acdefa", string(middle))

	end := getEncryptedObjectRange(t, tc, bktName, objName, 1<<16+2, len(content)-1)
	require.Equal(t, "aaaaaaaag", string(end))
}

func TestS3EncryptionSSECMultipartUpload(t *testing.T) {
	tc := prepareHandlerContext(t)
	bktName, objName := "bucket-for-sse-c-multipart-s3-tests", "multipart_enc"
	createTestBucket(tc, bktName)

	objLen := 30 * 1024 * 1024
	partSize := objLen / 6
	headerMetaKey := api.MetadataPrefix + "foo"
	headers := map[string]string{
		headerMetaKey:   "bar",
		api.ContentType: "text/plain",
	}

	data := multipartUploadEncrypted(t, tc, bktName, objName, headers, objLen, partSize)
	require.Equal(t, objLen, len(data))

	resData, resHeader := getEncryptedObject(t, tc, bktName, objName)
	equalDataSlices(t, data, resData)
	require.Equal(t, headers[api.ContentType], resHeader.Get(api.ContentType))
	require.Equal(t, headers[headerMetaKey], resHeader[headerMetaKey][0])
	require.Equal(t, strconv.Itoa(objLen), resHeader.Get(api.ContentLength))

	checkContentUsingRangeEnc(t, tc, bktName, objName, data, 1000000)
	checkContentUsingRangeEnc(t, tc, bktName, objName, data, 10000000)
}

func equalDataSlices(t *testing.T, expected, actual []byte) {
	require.Equal(t, len(expected), len(actual), "sizes don't match")

	if bytes.Equal(expected, actual) {
		return
	}

	for i := 0; i < len(expected); i++ {
		if expected[i] != actual[i] {
			require.Equalf(t, expected[i], actual[i], "differ start with '%d' position, length: %d", i, len(expected))
		}
	}
}

func checkContentUsingRangeEnc(t *testing.T, tc *handlerContext, bktName, objName string, data []byte, step int) {
	var off, toRead, end int

	for off < len(data) {
		toRead = len(data) - off
		if toRead > step {
			toRead = step
		}
		end = off + toRead - 1

		rangeData := getEncryptedObjectRange(t, tc, bktName, objName, off, end)
		equalDataSlices(t, data[off:end+1], rangeData)

		off += step
	}
}

func multipartUploadEncrypted(t *testing.T, tc *handlerContext, bktName, objName string, headers map[string]string, objLen, partsSize int) (objData []byte) {
	multipartInfo := createMultipartUpload(t, tc, bktName, objName, headers)

	var sum, currentPart int
	var etags []string
	adjustedSize := partsSize

	for sum < objLen {
		currentPart++

		sum += partsSize
		if sum > objLen {
			adjustedSize = objLen - sum
		}

		etag, data := uploadPart(t, tc, bktName, objName, multipartInfo.UploadID, currentPart, adjustedSize)
		etags = append(etags, etag)
		objData = append(objData, data...)
	}

	completeMultipartUpload(t, tc, bktName, objName, multipartInfo.UploadID, etags)
	return
}

func createMultipartUpload(t *testing.T, tc *handlerContext, bktName, objName string, headers map[string]string) *InitiateMultipartUploadResponse {
	w, r := prepareTestRequest(tc, bktName, objName, nil)
	setEncryptHeaders(r)
	setHeaders(r, headers)
	tc.Handler().CreateMultipartUploadHandler(w, r)
	multipartInitInfo := &InitiateMultipartUploadResponse{}
	readResponse(t, w, http.StatusOK, multipartInitInfo)

	return multipartInitInfo
}
func completeMultipartUpload(t *testing.T, tc *handlerContext, bktName, objName, uploadID string, partsETags []string) {
	query := make(url.Values)
	query.Set(uploadIDQuery, uploadID)
	complete := &CompleteMultipartUpload{
		Parts: []*layer.CompletedPart{},
	}
	for i, tag := range partsETags {
		complete.Parts = append(complete.Parts, &layer.CompletedPart{
			ETag:       tag,
			PartNumber: i + 1,
		})
	}

	w, r := prepareTestFullRequest(tc, bktName, objName, query, complete)
	tc.Handler().CompleteMultipartUploadHandler(w, r)
	assertStatus(t, w, http.StatusOK)
}

func uploadPart(t *testing.T, tc *handlerContext, bktName, objName, uploadID string, num, size int) (string, []byte) {
	partBody := make([]byte, size)
	_, err := rand.Read(partBody)
	require.NoError(t, err)

	query := make(url.Values)
	query.Set(uploadIDQuery, uploadID)
	query.Set(partNumberQuery, strconv.Itoa(num))

	w, r := prepareTestRequestWithQuery(tc, bktName, objName, query, partBody)
	setEncryptHeaders(r)
	tc.Handler().UploadPartHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	return w.Header().Get(api.ETag), partBody
}

func TestMultipartEncrypted(t *testing.T) {
	partSize := 5*1048576 + 1<<16 - 5 // 5MB (min part size) + 64kb (cipher block size) - 5 (to check corner range)

	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-sse-c-multipart", "object-to-encrypt-multipart"
	createTestBucket(tc, bktName)

	w, r := prepareTestRequest(tc, bktName, objName, nil)
	setEncryptHeaders(r)
	tc.Handler().CreateMultipartUploadHandler(w, r)
	multipartInitInfo := &InitiateMultipartUploadResponse{}
	readResponse(t, w, http.StatusOK, multipartInitInfo)

	part1 := make([]byte, partSize)
	for i := range part1 {
		part1[i] = 'a'
	}
	query := make(url.Values)
	query.Set(uploadIDQuery, multipartInitInfo.UploadID)
	query.Set(partNumberQuery, "1")
	w, r = prepareTestRequestWithQuery(tc, bktName, objName, query, part1)
	setEncryptHeaders(r)
	tc.Handler().UploadPartHandler(w, r)
	assertStatus(t, w, http.StatusOK)
	part1ETag := w.Header().Get(api.ETag)

	part2 := []byte("part2")
	query = make(url.Values)
	query.Set(uploadIDQuery, multipartInitInfo.UploadID)
	query.Set(partNumberQuery, "2")
	w, r = prepareTestRequestWithQuery(tc, bktName, objName, query, part2)
	setEncryptHeaders(r)
	tc.Handler().UploadPartHandler(w, r)
	assertStatus(t, w, http.StatusOK)
	part2ETag := w.Header().Get(api.ETag)

	query = make(url.Values)
	query.Set(uploadIDQuery, multipartInitInfo.UploadID)
	complete := &CompleteMultipartUpload{
		Parts: []*layer.CompletedPart{
			{ETag: part1ETag, PartNumber: 1},
			{ETag: part2ETag, PartNumber: 2},
		},
	}
	w, r = prepareTestFullRequest(tc, bktName, objName, query, complete)
	tc.Handler().CompleteMultipartUploadHandler(w, r)
	assertStatus(t, w, http.StatusOK)

	res, _ := getEncryptedObject(t, tc, bktName, objName)
	require.Equal(t, len(part1)+len(part2), len(res))
	require.Equal(t, append(part1, part2...), res)

	part2Range := getEncryptedObjectRange(t, tc, bktName, objName, len(part1), len(part1)+len(part2)-1)
	require.Equal(t, part2[0:], part2Range)
}

func putEncryptedObject(t *testing.T, tc *handlerContext, bktName, objName, content string) {
	body := bytes.NewReader([]byte(content))
	w, r := prepareTestPayloadRequest(tc, bktName, objName, body)
	setEncryptHeaders(r)
	tc.Handler().PutObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)
}

func getEncryptedObject(t *testing.T, tc *handlerContext, bktName, objName string) ([]byte, http.Header) {
	w, r := prepareTestRequest(tc, bktName, objName, nil)
	setEncryptHeaders(r)
	tc.Handler().GetObjectHandler(w, r)
	assertStatus(t, w, http.StatusOK)
	content, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)
	return content, w.Header()
}

func getEncryptedObjectRange(t *testing.T, tc *handlerContext, bktName, objName string, start, end int) []byte {
	w, r := prepareTestRequest(tc, bktName, objName, nil)
	setEncryptHeaders(r)
	r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	tc.Handler().GetObjectHandler(w, r)
	assertStatus(t, w, http.StatusPartialContent)
	content, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)
	return content
}

func setEncryptHeaders(r *http.Request) {
	r.Header.Set(api.AmzServerSideEncryptionCustomerAlgorithm, layer.AESEncryptionAlgorithm)
	r.Header.Set(api.AmzServerSideEncryptionCustomerKey, aes256Key)
	r.Header.Set(api.AmzServerSideEncryptionCustomerKeyMD5, aes256KeyMD5)
}

func setHeaders(r *http.Request, header map[string]string) {
	for key, val := range header {
		r.Header.Set(key, val)
	}
}
