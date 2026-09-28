package main

import (
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestFilterStoragePolicyEndpointsSkipsDifferentContractAfterZeroHash(t *testing.T) {
	firstInvoker := new(invoker.Invoker)
	secondInvoker := new(invoker.Invoker)
	zeroHash := util.Uint160{}
	secondHash := util.Uint160{2}
	secondClosed := false

	initializedEndpoints := filterStoragePolicyEndpoints([]storagePolicyEndpoint{
		{invoker: firstInvoker, contractHash: zeroHash, close: func() {}},
		{
			invoker:      secondInvoker,
			contractHash: secondHash,
			close: func() {
				secondClosed = true
			},
		},
	})

	require.True(t, secondClosed)
	require.Equal(t, zeroHash, initializedEndpoints.contractHash)
	require.Len(t, initializedEndpoints.invokers, 1)
	require.Same(t, firstInvoker, initializedEndpoints.invokers[0])
}
