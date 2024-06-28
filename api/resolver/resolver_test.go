package resolver

import (
	"testing"

	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/stretchr/testify/require"
)

func Test_nnsResolver_index(t *testing.T) {
	r := NewNNSResolver([]*rpcNNS.ContractReader{nil, nil, nil})
	indexes := []int{0, 1, 2, 0, 1, 2}

	for _, index := range indexes {
		require.Equal(t, index, r.index())
	}
}
