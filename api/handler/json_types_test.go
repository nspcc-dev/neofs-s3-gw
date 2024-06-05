package handler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type (
	testCase struct {
		Action stringOrSlice `json:"action"`
	}
)

func TestStringOrSlice(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var (
			payload = []byte(`{"action":"s3:PutObject"}`)
			obj     testCase
		)

		require.NoError(t, json.Unmarshal(payload, &obj))
		require.Equal(t, []string{"s3:PutObject"}, obj.Action.values)

		marshaled, err := json.Marshal(obj)
		require.NoError(t, err)
		require.Equal(t, payload, marshaled)
	})

	t.Run("wildcard", func(t *testing.T) {
		var (
			payload = []byte(`{"action":"*"}`)
			obj     testCase
		)

		require.NoError(t, json.Unmarshal(payload, &obj))
		require.Equal(t, []string{"*"}, obj.Action.values)

		marshaled, err := json.Marshal(obj)
		require.NoError(t, err)
		require.Equal(t, payload, marshaled)
	})

	t.Run("slice", func(t *testing.T) {
		var (
			payload = []byte(`{"action":["s3:PutObject","s3:GetObject"]}`)
			obj     testCase
		)

		require.NoError(t, json.Unmarshal(payload, &obj))
		require.Equal(t, []string{"s3:PutObject", "s3:GetObject"}, obj.Action.values)

		marshaled, err := json.Marshal(obj)
		require.NoError(t, err)
		require.Equal(t, payload, marshaled)
	})

	t.Run("single element slice", func(t *testing.T) {
		var (
			payload = []byte(`{"action":["s3:PutObject"]}`)
			obj     testCase
		)

		require.NoError(t, json.Unmarshal(payload, &obj))
		require.Equal(t, []string{"s3:PutObject"}, obj.Action.values)

		marshaled, err := json.Marshal(obj)
		require.NoError(t, err)

		// if only one element, marshalling makes it as a string, not a slice.
		singleElementPayload := []byte(`{"action":"s3:PutObject"}`)
		require.Equal(t, singleElementPayload, marshaled)
	})

	t.Run("single element slice, with spaces", func(t *testing.T) {
		var (
			payload = []byte(`{    "action"     :      [     "s3:PutObject"     ]     }`)
			obj     testCase
		)

		require.NoError(t, json.Unmarshal(payload, &obj))
		require.Equal(t, []string{"s3:PutObject"}, obj.Action.values)

		marshaled, err := json.Marshal(obj)
		require.NoError(t, err)

		// if only one element, marshalling makes it as a string, not a slice.
		singleElementPayload := []byte(`{"action":"s3:PutObject"}`)
		require.Equal(t, singleElementPayload, marshaled)
	})

	t.Run("nil slice", func(t *testing.T) {
		var (
			payload = []byte(`{}`)
			obj     testCase
		)

		require.NoError(t, json.Unmarshal(payload, &obj))
		require.Nil(t, obj.Action.values)

		marshaled, err := json.Marshal(obj)
		require.NoError(t, err)

		singleElementPayload := []byte(`{"action":[]}`)
		require.Equal(t, singleElementPayload, marshaled)
	})
}
