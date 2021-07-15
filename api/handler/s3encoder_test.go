package handler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPathEncoder(t *testing.T) {
	for _, tc := range []struct {
		key      string
		expected string
	}{
		{key: "simple", expected: "simple"},
		{key: "foo/bar", expected: "foo/bar"},
		{key: "foo+1/bar", expected: "foo%2B1/bar"},
		{key: "foo ab/bar", expected: "foo%20ab/bar"},
		{key: "p-%", expected: "p-%25"},
		{key: "p/", expected: "p/"},
		{key: "p/", expected: "p/"},
		{key: "~user", expected: "%7Euser"},
		{key: "*user", expected: "*user"},
		{key: "user+password", expected: "user%2Bpassword"},
		{key: "_user", expected: "_user"},
		{key: "firstname.lastname", expected: "firstname.lastname"},
	} {
		actual := s3PathEncode(tc.key, urlEncodingType)
		require.Equal(t, tc.expected, actual)
	}
}

func TestQueryEncoder(t *testing.T) {
	for _, tc := range []struct {
		key      string
		expected string
	}{
		{key: "simple", expected: "simple"},
		{key: "foo/bar", expected: "foo/bar"},
		{key: "foo+1/bar", expected: "foo%2B1/bar"},
		{key: "foo ab/bar", expected: "foo+ab/bar"},
		{key: "p-%", expected: "p-%25"},
		{key: "p/", expected: "p/"},
		{key: "p/", expected: "p/"},
		{key: "~user", expected: "%7Euser"},
		{key: "*user", expected: "*user"},
		{key: "user+password", expected: "user%2Bpassword"},
		{key: "_user", expected: "_user"},
		{key: "firstname.lastname", expected: "firstname.lastname"},
	} {
		actual := s3QueryEncode(tc.key, urlEncodingType)
		require.Equal(t, tc.expected, actual)
	}
}
