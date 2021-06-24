package handler

import (
	"net/http"
	"testing"

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
		{header: "bytes=0-256", expected: &layer.RangeParams{Start: 0, End: 256}, err: false},
		{header: "bytes=0-0", expected: &layer.RangeParams{Start: 0, End: 0}, err: false},
		{header: "bytes=0-", expected: &layer.RangeParams{Start: 0, End: 99}, fullSize: 100, err: false},
		{header: "bytes=-10", expected: &layer.RangeParams{Start: 90, End: 99}, fullSize: 100, err: false},
		{header: "", err: false},
		{header: "bytes=-1-256", err: true},
		{header: "bytes=256-0", err: true},
		{header: "bytes=string-0", err: true},
		{header: "bytes=0-string", err: true},
		{header: "bytes:0-256", err: true},
		{header: "bytes:-", err: true},
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
