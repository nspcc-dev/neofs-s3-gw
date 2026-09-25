package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/stretchr/testify/require"
)

type readerInitializationResult struct {
	reader *nns.ContractReader
	err    error
}

func TestNewNNSReadersSkipsFailedEndpoints(t *testing.T) {
	firstReader := new(nns.ContractReader)
	secondReader := new(nns.ContractReader)
	errUnavailable := errors.New("unavailable")

	for _, tc := range []struct {
		name            string
		results         map[string]readerInitializationResult
		expectedReaders []*nns.ContractReader
		expectedInvoked []string
	}{
		{
			name: "first endpoint",
			results: map[string]readerInitializationResult{
				"IR1-down": {err: errUnavailable},
				"IR2-up":   {reader: secondReader},
			},
			expectedReaders: []*nns.ContractReader{secondReader},
			expectedInvoked: []string{"IR1-down", "IR2-up"},
		},
		{
			name: "last endpoint",
			results: map[string]readerInitializationResult{
				"IR1-up":   {reader: firstReader},
				"IR2-down": {err: errUnavailable},
			},
			expectedReaders: []*nns.ContractReader{firstReader},
			expectedInvoked: []string{"IR1-up", "IR2-down"},
		},
		{
			name: "two healthy endpoints",
			results: map[string]readerInitializationResult{
				"IR1-up": {reader: firstReader},
				"IR2-up": {reader: secondReader},
			},
			expectedReaders: []*nns.ContractReader{firstReader, secondReader},
			expectedInvoked: []string{"IR1-up", "IR2-up"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invoked []string
			readers, err := newNNSReaders(context.Background(), tc.expectedInvoked, func(_ context.Context, endpoint string) (*nns.ContractReader, error) {
				invoked = append(invoked, endpoint)
				result := tc.results[endpoint]
				return result.reader, result.err
			})

			require.NoError(t, err)
			require.Equal(t, tc.expectedInvoked, invoked)
			require.Len(t, readers, len(tc.expectedReaders))
			for i := range tc.expectedReaders {
				require.Same(t, tc.expectedReaders[i], readers[i])
			}
		})
	}
}

func TestNewNNSReadersFailsAfterAllEndpointsFail(t *testing.T) {
	firstErr := errors.New("first endpoint unavailable")
	secondErr := errors.New("second endpoint unavailable")

	_, err := newNNSReaders(context.Background(), []string{"IR1-down", "IR2-down"}, func(_ context.Context, endpoint string) (*nns.ContractReader, error) {
		switch endpoint {
		case "IR1-down":
			return nil, firstErr
		case "IR2-down":
			return nil, secondErr
		default:
			t.Fatalf("unexpected endpoint %q", endpoint)
			return nil, nil
		}
	})

	require.ErrorContains(t, err, "all RPC endpoints failed")
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}
