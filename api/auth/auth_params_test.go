package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthParams(t *testing.T) {
	type param struct{ name, value string }

	for _, tc := range []struct {
		params   string
		expected []param
		err      bool
	}{
		{params: ""},
		{params: " , ,"},
		{params: "a=1", expected: []param{{"a", "1"}}},
		{params: "a=1, b=2,c=3", expected: []param{{"a", "1"}, {"b", "2"}, {"c", "3"}}},
		{params: ",a = 1 ,, b=\t2 ,", expected: []param{{"a", "1"}, {"b", "2"}}},
		{params: "a=", expected: []param{{"a", ""}}},
		{params: `a="x, y", b=2`, expected: []param{{"a", "x, y"}, {"b", "2"}}},
		{params: `a="x\"y"`, err: true},
		{params: `a="x\\y"`, err: true},
		{params: `a=""`, expected: []param{{"a", ""}}},
		{params: "a", err: true},
		{params: "=1", err: true},
		{params: "a b=1", err: true},
		{params: "a=1 2", err: true},
		{params: `a=x"y`, err: true},
		{params: `a="xy`, err: true},
		{params: `a="x"y`, err: true},
		{params: `a=1, "b"=2`, err: true},
	} {
		t.Run(tc.params, func(t *testing.T) {
			var (
				p      = authParams(tc.params)
				actual []param
				err    error
			)
			for {
				var name, value string
				if name, value, err = p.next(); err != nil || name == "" {
					break
				}
				actual = append(actual, param{name, value})
			}

			if tc.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}
