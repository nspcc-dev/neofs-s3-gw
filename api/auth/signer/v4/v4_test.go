package v4

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_stripExcessSpaces(t *testing.T) {
	type args struct {
		vals []string
	}
	tests := []struct {
		name     string
		args     args
		required args
	}{
		{name: "empty", args: args{vals: []string{}}, required: args{vals: []string{}}},
		{name: "same", args: args{vals: []string{"aaa"}}, required: args{vals: []string{"aaa"}}},

		{name: "3 in head", args: args{vals: []string{"   aaa"}}, required: args{vals: []string{"aaa"}}},
		{name: "2 in head", args: args{vals: []string{"  aaa"}}, required: args{vals: []string{"aaa"}}},
		{name: "1 in head", args: args{vals: []string{" aaa"}}, required: args{vals: []string{"aaa"}}},

		{name: "3 in tail", args: args{vals: []string{"aaa   "}}, required: args{vals: []string{"aaa"}}},
		{name: "2 in tail", args: args{vals: []string{"aaa  "}}, required: args{vals: []string{"aaa"}}},
		{name: "1 in tail", args: args{vals: []string{"aaa "}}, required: args{vals: []string{"aaa"}}},

		{name: "3 in both", args: args{vals: []string{"   aaa   "}}, required: args{vals: []string{"aaa"}}},
		{name: "2 in both", args: args{vals: []string{"  aaa  "}}, required: args{vals: []string{"aaa"}}},
		{name: "1 in both", args: args{vals: []string{" aaa "}}, required: args{vals: []string{"aaa"}}},

		{name: "two word with spaces", args: args{vals: []string{" aaa bbb "}}, required: args{vals: []string{"aaa bbb"}}},
		{name: "two word with 4 spaces", args: args{vals: []string{"    aaa   bbb    "}}, required: args{vals: []string{"aaa bbb"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stripExcessSpaces(tt.args.vals)
			require.ElementsMatch(t, tt.required.vals, tt.args.vals)
		})
	}
}
