package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/unwrap"
	"github.com/nspcc-dev/neo-go/pkg/util"
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/nspcc-dev/neofs-s3-gw/internal/models"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
)

type (
	storagePolicyProvider struct {
		invokers     []*invoker.Invoker
		contractHash util.Uint160

		mu   *sync.Mutex
		next uint32
	}

	noOpStoragePolicyProvider struct{}
)

func newStoragePolicyProvider(ctx context.Context, contractName string, endpoints []string) (*storagePolicyProvider, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("endpoints must be set")
	}

	var (
		invokers     = make([]*invoker.Invoker, 0, len(endpoints))
		contractHash util.Uint160
		zero         util.Uint160
	)

	for _, endpoint := range endpoints {
		cl, err := rpcClient(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("rpcclient: %w", err)
		}

		inv := invoker.New(cl, nil)

		// contract hash is not resolved.
		if contractHash.Equals(zero) {
			contractHash, err = resolveContract(cl, inv, contractName)

			if err != nil {
				return nil, fmt.Errorf("resolve %q contract: %w", contractName, err)
			}
		}

		invokers = append(invokers, inv)
	}

	return &storagePolicyProvider{
		contractHash: contractHash,
		invokers:     invokers,
		mu:           &sync.Mutex{},
	}, nil
}

func resolveContract(cl *rpcclient.Client, inv *invoker.Invoker, contractName string) (util.Uint160, error) {
	nnsReader, err := rpcNNS.NewInferredReader(cl, inv)
	if err != nil {
		return util.Uint160{}, fmt.Errorf("InferHash: %w", err)
	}

	contractHash, err := nnsReader.ResolveFSContract(contractName)
	if err != nil {
		return util.Uint160{}, fmt.Errorf("ResolveFSContract %q: %w", contractName, err)
	}

	return contractHash, nil
}

func (p *storagePolicyProvider) GetPlacementPolicy(userAddr util.Uint160, policyName string) (*netmap.PlacementPolicy, error) {
	payload, err := unwrap.Bytes(
		p.invoker().Call(p.contractHash, "resolvePolicy", userAddr, policyName),
	)

	if err != nil {
		if strings.Contains(err.Error(), "policy not found") {
			return nil, models.ErrNotFound
		}

		return nil, fmt.Errorf("get system storage policy: %w", err)
	}

	var pp netmap.PlacementPolicy
	if err = pp.UnmarshalJSON(payload); err != nil {
		return nil, fmt.Errorf("unmarshal placement policy: %w", err)
	}

	return &pp, nil
}

func (p *storagePolicyProvider) index() int {
	p.mu.Lock()

	p.next++
	index := (int(p.next) - 1) % len(p.invokers)

	if int(p.next) >= len(p.invokers) {
		p.next = 0
	}

	p.mu.Unlock()

	return index
}

func (p *storagePolicyProvider) invoker() *invoker.Invoker {
	return p.invokers[p.index()]
}

func rpcClient(ctx context.Context, endpoint string) (*rpcclient.Client, error) {
	cl, err := rpcclient.New(ctx, endpoint, rpcclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("new: %w", err)
	}

	if err = cl.Init(); err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}

	return cl, nil
}

func (p *noOpStoragePolicyProvider) GetPlacementPolicy(_ util.Uint160, _ string) (*netmap.PlacementPolicy, error) {
	return nil, models.ErrNotFound
}
