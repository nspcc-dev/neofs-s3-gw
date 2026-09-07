package neofs

import (
	"math/big"
	"testing"

	"github.com/nspcc-dev/neofs-contract/rpc/netmap"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func newNode(state *big.Int, addresses ...string) *netmap.NetmapNode2 {
	return &netmap.NetmapNode2{Addresses: addresses, State: state}
}

func TestNetmapEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name  string
		nodes []*netmap.NetmapNode2
		want  []string
	}{
		{
			name: "only online nodes",
			nodes: []*netmap.NetmapNode2{
				newNode(netmap.NodeStateOnline, "one:8080"),
				newNode(netmap.NodeStateOffline, "two:8080"),
				newNode(netmap.NodeStateMaintenance, "three:8080"),
				newNode(netmap.NodeStateOnline, "four:8080"),
			},
			want: []string{"one:8080", "four:8080"},
		},
		{
			name: "duplicates dropped",
			nodes: []*netmap.NetmapNode2{
				newNode(netmap.NodeStateOnline, "one:8080"),
				newNode(netmap.NodeStateOnline, "one:8080"),
			},
			want: []string{"one:8080"},
		},
		{
			name: "nodes without usable address skipped",
			nodes: []*netmap.NetmapNode2{
				newNode(netmap.NodeStateOnline, "http://one:8080"),
				newNode(netmap.NodeStateOnline, "two:8080"),
			},
			want: []string{"two:8080"},
		},
		{
			name: "first usable address taken",
			nodes: []*netmap.NetmapNode2{
				newNode(netmap.NodeStateOnline, "http://one:8080", "grpcs://one:8081", "one:8080"),
			},
			want: []string{"grpcs://one:8081"},
		},
		{
			name:  "node without state skipped",
			nodes: []*netmap.NetmapNode2{newNode(nil, "one:8080")},
		},
		{
			name:  "no online nodes",
			nodes: []*netmap.NetmapNode2{newNode(netmap.NodeStateOffline, "one:8080")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, netmapEndpoints(zaptest.NewLogger(t), tc.nodes))
		})
	}
}
