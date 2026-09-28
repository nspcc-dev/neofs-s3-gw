package fschain

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForEachEndpointContinuesAfterFailure(t *testing.T) {
	errUnavailable := errors.New("unavailable")
	var attempted []string
	var initialized []string

	err := ForEachEndpoint([]string{"IR1-down", "IR2-up", "IR3-up"}, func(endpoint string) error {
		attempted = append(attempted, endpoint)
		if endpoint == "IR1-down" {
			return errUnavailable
		}

		initialized = append(initialized, endpoint)
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, []string{"IR1-down", "IR2-up", "IR3-up"}, attempted)
	require.Equal(t, []string{"IR2-up", "IR3-up"}, initialized)
}

func TestForEachEndpointFailsWhenAllEndpointsFail(t *testing.T) {
	firstErr := errors.New("first endpoint unavailable")
	secondErr := errors.New("second endpoint unavailable")

	err := ForEachEndpoint([]string{"IR1-down", "IR2-down"}, func(endpoint string) error {
		switch endpoint {
		case "IR1-down":
			return firstErr
		case "IR2-down":
			return secondErr
		default:
			t.Fatalf("unexpected endpoint %q", endpoint)
			return nil
		}
	})

	require.ErrorContains(t, err, "all RPC endpoints failed")
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}

func TestForEachEndpointFailsForEmptyList(t *testing.T) {
	called := false

	err := ForEachEndpoint([]string{}, func(string) error {
		called = true
		return nil
	})

	require.ErrorContains(t, err, "endpoints must be set")
	require.False(t, called)
}
