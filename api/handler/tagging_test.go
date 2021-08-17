package handler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagsValidity(t *testing.T) {
	sbKey := strings.Builder{}
	for i := 0; i < keyTagMaxLength; i++ {
		sbKey.WriteByte('a')
	}
	sbValue := strings.Builder{}
	for i := 0; i < valueTagMaxLength; i++ {
		sbValue.WriteByte('a')
	}

	for _, tc := range []struct {
		tag   Tag
		valid bool
	}{
		{tag: Tag{}, valid: false},
		{tag: Tag{Key: "", Value: "1"}, valid: false},
		{tag: Tag{Key: "aws:key", Value: "val"}, valid: false},
		{tag: Tag{Key: "key~", Value: "val"}, valid: false},
		{tag: Tag{Key: "key\\", Value: "val"}, valid: false},
		{tag: Tag{Key: "key?", Value: "val"}, valid: false},
		{tag: Tag{Key: sbKey.String() + "b", Value: "val"}, valid: false},
		{tag: Tag{Key: "key", Value: sbValue.String() + "b"}, valid: false},

		{tag: Tag{Key: sbKey.String(), Value: "val"}, valid: true},
		{tag: Tag{Key: "key", Value: sbValue.String()}, valid: true},
		{tag: Tag{Key: "k e y", Value: "v a l"}, valid: true},
		{tag: Tag{Key: "12345", Value: "1234"}, valid: true},
		{tag: Tag{Key: allowedTagChars, Value: allowedTagChars}, valid: true},
	} {
		err := checkTag(tc.tag)
		if tc.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}
