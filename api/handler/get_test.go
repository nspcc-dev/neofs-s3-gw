package handler

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/stretchr/testify/require"
)

func TestFetchRangeHeader(t *testing.T) {
	for _, tc := range []struct {
		header   string
		expected layer.PayloadRange
		err      bool
	}{
		{header: "bytes=0-256", expected: layer.NewPayloadRangeBounds(0, 256)},
		{header: "bytes=0-0", expected: layer.NewPayloadRangeBounds(0, 0)},
		{header: "bytes=0-", expected: layer.NewPayloadRangeFrom(0)},
		{header: "bytes=10-", expected: layer.NewPayloadRangeFrom(10)},
		{header: "bytes=-10", expected: layer.NewPayloadRangeSuffix(10)},
		{header: ""},
		{header: "bytes=-0", err: true},
		{header: "bytes=-1-256", err: true},
		{header: "bytes=256-0", err: true},
		{header: "bytes=string-0", err: true},
		{header: "bytes=0-string", err: true},
		{header: "bytes:0-256", err: true},
		{header: "bytes:-", err: true},
	} {
		t.Run(tc.header, func(t *testing.T) {
			h := make(http.Header)
			h.Add("Range", tc.header)
			rng, err := fetchRangeHeader(h)
			if tc.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, rng)
		})
	}
}

func TestResolveRangeParams(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rng      layer.PayloadRange
		fullSize uint64
		expected *layer.RangeParams
		err      bool
	}{
		{name: "unset", rng: layer.PayloadRange{}, fullSize: 100},
		{name: "bounds", rng: layer.NewPayloadRangeBounds(0, 256), fullSize: 257, expected: &layer.RangeParams{Start: 0, End: 256}},
		{name: "bounds trimmed", rng: layer.NewPayloadRangeBounds(0, 256), fullSize: 256, expected: &layer.RangeParams{Start: 0, End: 255}},
		{name: "bounds single byte", rng: layer.NewPayloadRangeBounds(0, 0), fullSize: 1, expected: &layer.RangeParams{Start: 0, End: 0}},
		{name: "bounds past end", rng: layer.NewPayloadRangeBounds(10, 20), fullSize: 5, err: true},
		{name: "bounds empty object", rng: layer.NewPayloadRangeBounds(0, 0), fullSize: 0, err: true},
		{name: "from", rng: layer.NewPayloadRangeFrom(0), fullSize: 100, expected: &layer.RangeParams{Start: 0, End: 99}},
		{name: "from offset", rng: layer.NewPayloadRangeFrom(90), fullSize: 100, expected: &layer.RangeParams{Start: 90, End: 99}},
		{name: "from past end", rng: layer.NewPayloadRangeFrom(100), fullSize: 100, err: true},
		{name: "suffix", rng: layer.NewPayloadRangeSuffix(10), fullSize: 100, expected: &layer.RangeParams{Start: 90, End: 99}},
		{name: "suffix trimmed", rng: layer.NewPayloadRangeSuffix(200), fullSize: 100, expected: &layer.RangeParams{Start: 0, End: 99}},
		{name: "suffix empty object", rng: layer.NewPayloadRangeSuffix(10), fullSize: 0, err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := resolveRangeParams(tc.rng, tc.fullSize)
			if tc.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, params)
		})
	}
}

func newInfo(etag string, created time.Time) *data.ObjectInfo {
	return &data.ObjectInfo{
		HashSum: etag,
		Created: created,
	}
}

func TestPreconditions(t *testing.T) {
	today := time.Now()
	yesterday := today.Add(-24 * time.Hour)
	etag := "etag"
	etag2 := "etag2"

	for _, tc := range []struct {
		name     string
		info     *data.ObjectInfo
		args     *conditionalArgs
		expected error
	}{
		{
			name:     "no conditions",
			info:     new(data.ObjectInfo),
			args:     new(conditionalArgs),
			expected: nil,
		},
		{
			name:     "IfMatch true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfMatch: etag},
			expected: nil,
		},
		{
			name:     "IfMatch false",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfMatch: etag2},
			expected: s3errors.GetAPIError(s3errors.ErrPreconditionFailed)},
		{
			name:     "IfNoneMatch true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfNoneMatch: etag2},
			expected: nil},
		{
			name:     "IfNoneMatch false",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfNoneMatch: etag},
			expected: s3errors.GetAPIError(s3errors.ErrNotModified)},
		{
			name:     "IfModifiedSince true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfModifiedSince: &yesterday},
			expected: nil},
		{
			name:     "IfModifiedSince false",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfModifiedSince: &today},
			expected: s3errors.GetAPIError(s3errors.ErrNotModified)},
		{
			name:     "IfUnmodifiedSince true",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfUnmodifiedSince: &today},
			expected: nil},
		{
			name:     "IfUnmodifiedSince false",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfUnmodifiedSince: &yesterday},
			expected: s3errors.GetAPIError(s3errors.ErrPreconditionFailed)},

		{
			name:     "IfMatch true, IfUnmodifiedSince false",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfMatch: etag, IfUnmodifiedSince: &yesterday},
			expected: nil,
		},
		{
			name:     "IfMatch false, IfUnmodifiedSince true",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfMatch: etag2, IfUnmodifiedSince: &today},
			expected: s3errors.GetAPIError(s3errors.ErrPreconditionFailed),
		},
		{
			name:     "IfNoneMatch false, IfModifiedSince true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfNoneMatch: etag, IfModifiedSince: &yesterday},
			expected: s3errors.GetAPIError(s3errors.ErrNotModified),
		},
		{
			name:     "IfNoneMatch true, IfModifiedSince false",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfNoneMatch: etag2, IfModifiedSince: &today},
			expected: s3errors.GetAPIError(s3errors.ErrNotModified),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := checkPreconditions(tc.info, tc.args)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestGetRange(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-range", "object-to-range"
	createTestBucket(tc, bktName)

	content := "123456789abcdef"
	putObjectContent(tc, bktName, objName, content)

	full := getObjectRange(t, tc, bktName, objName, 0, len(content)-1)
	require.Equal(t, content, string(full))

	beginning := getObjectRange(t, tc, bktName, objName, 0, 3)
	require.Equal(t, content[:4], string(beginning))

	middle := getObjectRange(t, tc, bktName, objName, 5, 10)
	require.Equal(t, "6789ab", string(middle))

	end := getObjectRange(t, tc, bktName, objName, 10, 15)
	require.Equal(t, "bcdef", string(end))
}

func TestGetRangeForms(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-range-forms", "object-to-range"
	createTestBucket(tc, bktName)

	const content = "123456789abcdef" // 15 bytes.
	putObjectContent(tc, bktName, objName, content)

	for _, tt := range []struct {
		rng          string
		expected     string
		contentRange string
	}{
		{rng: "bytes=5-", expected: content[5:], contentRange: "bytes 5-14/15"},
		{rng: "bytes=0-", expected: content, contentRange: "bytes 0-14/15"},
		{rng: "bytes=-5", expected: content[10:], contentRange: "bytes 10-14/15"},
		{rng: "bytes=-100", expected: content, contentRange: "bytes 0-14/15"},
		{rng: "bytes=0-100", expected: content, contentRange: "bytes 0-14/15"},
		{rng: "bytes=14-14", expected: content[14:], contentRange: "bytes 14-14/15"},
	} {
		t.Run(tt.rng, func(t *testing.T) {
			w, r := prepareTestRequest(tc, bktName, objName, nil)
			r.Header.Set("Range", tt.rng)
			tc.Handler().GetObjectHandler(w, r)
			assertStatus(t, w, http.StatusPartialContent)

			resp := w.Result()
			defer resp.Body.Close()

			require.Equal(t, tt.contentRange, resp.Header.Get(api.ContentRange))
			require.Equal(t, strconv.Itoa(len(tt.expected)), resp.Header.Get(api.ContentLength))

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(body))
		})
	}
}

func TestGetRangeUnsatisfiable(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-bad-range", "object-to-range"
	createTestBucket(tc, bktName)

	const content = "123456789abcdef" // 15 bytes.
	putObjectContent(tc, bktName, objName, content)

	for _, rng := range []string{
		"bytes=15-",
		"bytes=20-30",
		"bytes=-0",
	} {
		t.Run(rng, func(t *testing.T) {
			w, r := prepareTestRequest(tc, bktName, objName, nil)
			r.Header.Set("Range", rng)
			tc.Handler().GetObjectHandler(w, r)
			assertS3Error(t, w, s3errors.GetAPIError(s3errors.ErrInvalidRange))
		})
	}
}

func TestGetObjectPartNumber(t *testing.T) {
	hc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-part-number", "object-multipart"
	createTestBucket(hc, bktName)

	multipartInfo := createMultipartUpload(hc, bktName, objName, map[string]string{})
	etag1, _ := uploadPart(hc, bktName, objName, multipartInfo.UploadID, 1, 5*1048576)
	etag2, part2 := uploadPart(hc, bktName, objName, multipartInfo.UploadID, 2, 10)
	completeMultipartUpload(hc, bktName, objName, multipartInfo.UploadID, []string{etag1, etag2})

	query := make(url.Values)
	query.Set("partNumber", "2")

	t.Run("whole part", func(t *testing.T) {
		w, r := prepareTestRequestWithQuery(hc, bktName, objName, query, nil)
		hc.Handler().GetObjectHandler(w, r)
		assertStatus(t, w, http.StatusOK)

		resp := w.Result()
		defer resp.Body.Close()

		require.Equal(t, "2", resp.Header.Get("x-amz-mp-parts-count"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, part2, body)
	})

	t.Run("ranged part", func(t *testing.T) {
		w, r := prepareTestRequestWithQuery(hc, bktName, objName, query, nil)
		r.Header.Set("Range", "bytes=-4")
		hc.Handler().GetObjectHandler(w, r)
		assertStatus(t, w, http.StatusPartialContent)

		resp := w.Result()
		defer resp.Body.Close()

		require.Equal(t, "bytes 6-9/10", resp.Header.Get(api.ContentRange))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, part2[6:], body)
	})
}

func putObjectContent(hc *handlerContext, bktName, objName, content string) {
	body := bytes.NewReader([]byte(content))
	w, r := prepareTestPayloadRequest(hc, bktName, objName, body)
	hc.Handler().PutObjectHandler(w, r)
	assertStatus(hc.t, w, http.StatusOK)
}

func getObjectRange(t *testing.T, tc *handlerContext, bktName, objName string, start, end int) []byte {
	w, r := prepareTestRequest(tc, bktName, objName, nil)
	r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	tc.Handler().GetObjectHandler(w, r)
	assertStatus(t, w, http.StatusPartialContent)
	body := w.Result().Body
	content, err := io.ReadAll(body)
	body.Close()
	require.NoError(t, err)
	return content
}

func TestGetObject_noNeoFSSystemAttributes(t *testing.T) {
	tc := prepareHandlerContext(t)

	bktName, objName := "bucket-for-neofs-attributes", "object-to-neofs-attributes"
	createTestBucket(tc, bktName)

	content := "123456789abcdef1"
	putObjectContent(tc, bktName, objName, content)

	w, r := prepareTestRequest(tc, bktName, objName, nil)
	tc.Handler().GetObjectHandler(w, r)

	assertStatus(t, w, http.StatusOK)
	_ = w.Result().Body.Close()

	for k := range w.Result().Header {
		require.False(t, strings.HasPrefix(k, "X-Amz-Meta-__NEOFS__"))
	}
}
