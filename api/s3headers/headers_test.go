package s3headers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoredHeadersRoundTrip(t *testing.T) {
	in := map[string]string{"owner": "smoke", "note": "", "flag": "", "Content-Type": "text/plain"}
	want := map[string]string{
		"owner":                "smoke",
		"Content-Type":         "text/plain",
		AttributeEmptyMetaKeys: "flag,note",
	}

	stored := GetStoredHeaders(in)
	require.Equal(t, want, stored)
	for _, v := range stored {
		require.NotEmpty(t, v, "every stored attribute value must be non-empty")
	}

	fromAttrs := map[string]string{}
	for _, a := range GetMetaAttributes(in) {
		fromAttrs[a.Key()] = a.Value()
	}
	require.Equal(t, want, fromAttrs)

	RestoreEmptyHeaders(stored)
	require.Equal(t, in, stored)

	none := GetStoredHeaders(map[string]string{"owner": "smoke"})
	require.Equal(t, map[string]string{"owner": "smoke"}, none)
	RestoreEmptyHeaders(none)
	require.Equal(t, map[string]string{"owner": "smoke"}, none)
}
