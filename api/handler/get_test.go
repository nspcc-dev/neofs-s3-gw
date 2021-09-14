package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/stretchr/testify/require"
)

func TestFetchRangeHeader(t *testing.T) {
	for _, tc := range []struct {
		header   string
		expected *layer.RangeParams
		fullSize uint64
		err      bool
	}{
		{header: "bytes=0-256", expected: &layer.RangeParams{Start: 0, End: 256}, fullSize: 257, err: false},
		{header: "bytes=0-0", expected: &layer.RangeParams{Start: 0, End: 0}, fullSize: 1, err: false},
		{header: "bytes=0-256", expected: &layer.RangeParams{Start: 0, End: 255}, fullSize: 256, err: false},
		{header: "bytes=0-", expected: &layer.RangeParams{Start: 0, End: 99}, fullSize: 100, err: false},
		{header: "bytes=-10", expected: &layer.RangeParams{Start: 90, End: 99}, fullSize: 100, err: false},
		{header: "", err: false},
		{header: "bytes=-1-256", err: true},
		{header: "bytes=256-0", err: true},
		{header: "bytes=string-0", err: true},
		{header: "bytes=0-string", err: true},
		{header: "bytes:0-256", err: true},
		{header: "bytes:-", err: true},
		{header: "bytes=0-0", fullSize: 0, err: true},
		{header: "bytes=10-20", fullSize: 5, err: true},
	} {
		h := make(http.Header)
		h.Add("Range", tc.header)
		params, err := fetchRangeHeader(h, tc.fullSize)
		if tc.err {
			require.Error(t, err)
			continue
		}

		require.NoError(t, err)
		require.Equal(t, tc.expected, params)
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
			expected: errors.GetAPIError(errors.ErrPreconditionFailed)},
		{
			name:     "IfNoneMatch true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfNoneMatch: etag2},
			expected: nil},
		{
			name:     "IfNoneMatch false",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfNoneMatch: etag},
			expected: errors.GetAPIError(errors.ErrNotModified)},
		{
			name:     "IfModifiedSince true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfModifiedSince: &yesterday},
			expected: nil},
		{
			name:     "IfModifiedSince false",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfModifiedSince: &today},
			expected: errors.GetAPIError(errors.ErrNotModified)},
		{
			name:     "IfUnmodifiedSince true",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfUnmodifiedSince: &today},
			expected: nil},
		{
			name:     "IfUnmodifiedSince false",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfUnmodifiedSince: &yesterday},
			expected: errors.GetAPIError(errors.ErrPreconditionFailed)},

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
			expected: errors.GetAPIError(errors.ErrPreconditionFailed),
		},
		{
			name:     "IfNoneMatch false, IfModifiedSince true",
			info:     newInfo(etag, today),
			args:     &conditionalArgs{IfNoneMatch: etag, IfModifiedSince: &yesterday},
			expected: errors.GetAPIError(errors.ErrNotModified),
		},
		{
			name:     "IfNoneMatch true, IfModifiedSince false",
			info:     newInfo(etag, yesterday),
			args:     &conditionalArgs{IfNoneMatch: etag2, IfModifiedSince: &today},
			expected: errors.GetAPIError(errors.ErrNotModified),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := checkPreconditions(tc.info, tc.args)
			require.Equal(t, tc.expected, actual)
		})
	}
}
