package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/stretchr/testify/require"
)

type storagePolicyEndpointResult struct {
	endpoint storagePolicyEndpoint
	err      error
}

func TestNewStoragePolicyEndpointsSkipsFailedEndpoints(t *testing.T) {
	firstInvoker := new(invoker.Invoker)
	secondInvoker := new(invoker.Invoker)
	contractHash := util.Uint160{1}
	errUnavailable := errors.New("unavailable")

	for _, tc := range []struct {
		name             string
		results          map[string]storagePolicyEndpointResult
		expectedInvokers []*invoker.Invoker
		expectedInvoked  []string
	}{
		{
			name: "first endpoint",
			results: map[string]storagePolicyEndpointResult{
				"IR1-down": {err: errUnavailable},
				"IR2-up": {
					endpoint: storagePolicyEndpoint{invoker: secondInvoker, contractHash: contractHash, close: func() {}},
				},
			},
			expectedInvokers: []*invoker.Invoker{secondInvoker},
			expectedInvoked:  []string{"IR1-down", "IR2-up"},
		},
		{
			name: "last endpoint",
			results: map[string]storagePolicyEndpointResult{
				"IR1-up": {
					endpoint: storagePolicyEndpoint{invoker: firstInvoker, contractHash: contractHash, close: func() {}},
				},
				"IR2-down": {err: errUnavailable},
			},
			expectedInvokers: []*invoker.Invoker{firstInvoker},
			expectedInvoked:  []string{"IR1-up", "IR2-down"},
		},
		{
			name: "two healthy endpoints",
			results: map[string]storagePolicyEndpointResult{
				"IR1-up": {
					endpoint: storagePolicyEndpoint{invoker: firstInvoker, contractHash: contractHash, close: func() {}},
				},
				"IR2-up": {
					endpoint: storagePolicyEndpoint{invoker: secondInvoker, contractHash: contractHash, close: func() {}},
				},
			},
			expectedInvokers: []*invoker.Invoker{firstInvoker, secondInvoker},
			expectedInvoked:  []string{"IR1-up", "IR2-up"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var invoked []string
			initializedEndpoints, err := newStoragePolicyEndpoints(
				context.Background(),
				"storage-policy",
				tc.expectedInvoked,
				func(_ context.Context, endpoint, contractName string) (storagePolicyEndpoint, error) {
					require.Equal(t, "storage-policy", contractName)
					invoked = append(invoked, endpoint)
					result := tc.results[endpoint]
					return result.endpoint, result.err
				},
			)

			require.NoError(t, err)
			require.Equal(t, tc.expectedInvoked, invoked)
			require.Equal(t, contractHash, initializedEndpoints.contractHash)
			require.Len(t, initializedEndpoints.invokers, len(tc.expectedInvokers))
			for i := range tc.expectedInvokers {
				require.Same(t, tc.expectedInvokers[i], initializedEndpoints.invokers[i])
			}
		})
	}
}

func TestNewStoragePolicyEndpointsFailsAfterAllEndpointsFail(t *testing.T) {
	firstErr := errors.New("first endpoint unavailable")
	secondErr := errors.New("second endpoint unavailable")

	_, err := newStoragePolicyEndpoints(
		context.Background(),
		"storage-policy",
		[]string{"IR1-down", "IR2-down"},
		func(_ context.Context, endpoint, _ string) (storagePolicyEndpoint, error) {
			switch endpoint {
			case "IR1-down":
				return storagePolicyEndpoint{}, firstErr
			case "IR2-down":
				return storagePolicyEndpoint{}, secondErr
			default:
				t.Fatalf("unexpected endpoint %q", endpoint)
				return storagePolicyEndpoint{}, nil
			}
		},
	)

	require.ErrorContains(t, err, "all RPC endpoints failed")
	require.ErrorIs(t, err, firstErr)
	require.ErrorIs(t, err, secondErr)
}

func TestNewStoragePolicyEndpointsSkipsDifferentContractAfterZeroHash(t *testing.T) {
	firstInvoker := new(invoker.Invoker)
	secondInvoker := new(invoker.Invoker)
	zeroHash := util.Uint160{}
	secondHash := util.Uint160{2}
	secondClosed := false

	initializedEndpoints, err := newStoragePolicyEndpoints(
		context.Background(),
		"storage-policy",
		[]string{"IR1-zero-hash", "IR2-wrong-contract"},
		func(_ context.Context, endpoint, _ string) (storagePolicyEndpoint, error) {
			switch endpoint {
			case "IR1-zero-hash":
				return storagePolicyEndpoint{invoker: firstInvoker, contractHash: zeroHash, close: func() {}}, nil
			case "IR2-wrong-contract":
				return storagePolicyEndpoint{
					invoker:      secondInvoker,
					contractHash: secondHash,
					close: func() {
						secondClosed = true
					},
				}, nil
			default:
				t.Fatalf("unexpected endpoint %q", endpoint)
				return storagePolicyEndpoint{}, nil
			}
		},
	)

	require.NoError(t, err)
	require.True(t, secondClosed)
	require.Equal(t, zeroHash, initializedEndpoints.contractHash)
	require.Len(t, initializedEndpoints.invokers, 1)
	require.Same(t, firstInvoker, initializedEndpoints.invokers[0])
}
