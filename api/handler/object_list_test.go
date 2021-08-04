package handler

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseContinuationToken(t *testing.T) {
	var err error

	t.Run("empty token", func(t *testing.T) {
		var queryValues = map[string][]string{
			"continuation-token": {""},
		}
		_, err = parseContinuationToken(queryValues)
		require.Error(t, err)
	})

	t.Run("invalid not empty token", func(t *testing.T) {
		var queryValues = map[string][]string{
			"continuation-token": {"asd"},
		}
		_, err = parseContinuationToken(queryValues)
		require.Error(t, err)
	})

	t.Run("valid token", func(t *testing.T) {
		tokenStr := "75BTT5Z9o79XuKdUeGqvQbqDnxu6qWcR5EhxW8BXFf8t"
		var queryValues = map[string][]string{
			"continuation-token": {tokenStr},
		}
		token, err := parseContinuationToken(queryValues)
		require.NoError(t, err)
		require.Equal(t, tokenStr, token)
	})
}
