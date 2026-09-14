package neofs

import (
	"context"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/vm/stackitem"
	"github.com/nspcc-dev/neofs-contract/rpc/netmap"
	"go.uber.org/zap"
)

// NetmapNodes returns addresses of the storage nodes that are online in the NeoFS network map.
func NetmapNodes(ctx context.Context, log *zap.Logger, rpcEndpoints []string, netMapContract util.Uint160) ([]string, error) {
	var opts rpcclient.Options

	log = log.Named("netmapNodes")

	for _, endpoint := range rpcEndpoints {
		cl, err := rpcclient.New(ctx, endpoint, opts)
		if err != nil {
			log.Info("could not instantiate RPC client", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}
		defer cl.Close()

		if err = cl.Init(); err != nil {
			log.Info("could not initialize RPC client", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}

		var inv = invoker.New(cl, nil)

		nodes, err := listNodes(inv, netmap.NewReader(inv, netMapContract))
		if err != nil {
			log.Info("could not list netmap nodes", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}

		return netmapEndpoints(log, nodes), nil
	}

	return nil, errors.New("could not read network map from any RPC endpoint")
}

func listNodes(inv *invoker.Invoker, reader *netmap.ContractReader) ([]*netmap.NetmapNode2, error) {
	sess, iter, err := reader.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	defer func() {
		_ = inv.TerminateSession(sess)
	}()

	var nodes []*netmap.NetmapNode2

	for {
		items, err := inv.TraverseIterator(sess, &iter, 0)
		if err != nil {
			return nil, fmt.Errorf("traverse nodes: %w", err)
		}

		if len(items) == 0 {
			return nodes, nil
		}

		batch, err := decodeNodes(items)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, batch...)
	}
}

func decodeNodes(items []stackitem.Item) ([]*netmap.NetmapNode2, error) {
	var nodes = make([]*netmap.NetmapNode2, 0, len(items))

	for _, item := range items {
		node := new(netmap.NetmapNode2)
		if err := node.FromStackItem(item); err != nil {
			return nil, fmt.Errorf("decode netmap node: %w", err)
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

func netmapEndpoints(log *zap.Logger, nodes []*netmap.NetmapNode2) []string {
	var (
		endpoints []string
		seen      = make(map[string]struct{}, len(nodes))
	)

	for _, node := range nodes {
		if node.State == nil || node.State.Cmp(netmap.NodeStateOnline) != 0 {
			if node.Key != nil {
				log.Info("node has invalid state, or state is not online", zap.String("node_key", node.Key.StringCompressed()))
			}

			continue
		}

		endpoint, ok := nodeEndpoint(node.Addresses)
		if !ok {
			log.Debug("skip node with no usable address", zap.Strings("addresses", node.Addresses))
			continue
		}

		if _, ok = seen[endpoint]; ok {
			continue
		}

		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints
}

func nodeEndpoint(addresses []string) (string, bool) {
	for _, addr := range addresses {
		if uri, err := nodeAddressToURI(addr); err == nil {
			return uri, true
		}
	}

	return "", false
}
