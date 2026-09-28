package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/unwrap"
	"github.com/nspcc-dev/neo-go/pkg/util"
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
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

	// storagePolicyEndpoint contains initialized policy resources and their cleanup function.
	storagePolicyEndpoint struct {
		invoker      *invoker.Invoker
		contractHash util.Uint160
		close        func()
	}

	// storagePolicyEndpointInitializer initializes policy resources for an endpoint.
	storagePolicyEndpointInitializer func(context.Context, string, string) (storagePolicyEndpoint, error)

	// storagePolicyEndpoints contains invokers that use the same policy contract.
	storagePolicyEndpoints struct {
		invokers     []*invoker.Invoker
		contractHash util.Uint160
	}

	noOpStoragePolicyProvider struct{}
)

func newStoragePolicyProvider(ctx context.Context, contractName string, endpoints []string) (*storagePolicyProvider, error) {
	initializedEndpoints, err := newStoragePolicyEndpoints(ctx, contractName, endpoints, newStoragePolicyEndpoint)
	if err != nil {
		return nil, err
	}

	return &storagePolicyProvider{
		contractHash: initializedEndpoints.contractHash,
		invokers:     initializedEndpoints.invokers,
		mu:           &sync.Mutex{},
	}, nil
}

func newStoragePolicyEndpoints(
	ctx context.Context,
	contractName string,
	endpoints []string,
	initialize storagePolicyEndpointInitializer,
) (storagePolicyEndpoints, error) {
	if len(endpoints) == 0 {
		return storagePolicyEndpoints{}, errors.New("endpoints must be set")
	}

	var (
		invokers        = make([]*invoker.Invoker, 0, len(endpoints))
		contractHash    util.Uint160
		hasContractHash bool
		errs            []error
	)

	for _, endpoint := range endpoints {
		initializedEndpoint, err := initialize(ctx, endpoint, contractName)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", endpoint, err))
			continue
		}

		if !hasContractHash {
			contractHash = initializedEndpoint.contractHash
			hasContractHash = true
		} else if !contractHash.Equals(initializedEndpoint.contractHash) {
			initializedEndpoint.close()
			errs = append(errs, fmt.Errorf("%q: resolved contract hash differs from other endpoints", endpoint))
			continue
		}

		invokers = append(invokers, initializedEndpoint.invoker)
	}

	if len(invokers) == 0 {
		return storagePolicyEndpoints{}, fmt.Errorf("all RPC endpoints failed: %w", errors.Join(errs...))
	}

	return storagePolicyEndpoints{
		contractHash: contractHash,
		invokers:     invokers,
	}, nil
}

func newStoragePolicyEndpoint(ctx context.Context, endpoint, contractName string) (storagePolicyEndpoint, error) {
	cl, err := rpcClient(ctx, endpoint)
	if err != nil {
		return storagePolicyEndpoint{}, fmt.Errorf("rpcclient: %w", err)
	}

	inv := invoker.New(cl, nil)
	contractHash, err := resolveContract(cl, inv, contractName)
	if err != nil {
		cl.Close()
		return storagePolicyEndpoint{}, fmt.Errorf("resolve %q contract: %w", contractName, err)
	}

	return storagePolicyEndpoint{
		invoker:      inv,
		contractHash: contractHash,
		close:        cl.Close,
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

func (p *storagePolicyProvider) GetPlacementPolicy(userAddr util.Uint160, policyName string) (layer.PlacementPolicy, error) {
	payload, err := unwrap.Bytes(
		p.invoker().Call(p.contractHash, "resolvePolicy", userAddr, policyName),
	)

	if err != nil {
		if strings.Contains(err.Error(), "policy not found") {
			return layer.PlacementPolicy{}, models.ErrNotFound
		}

		return layer.PlacementPolicy{}, fmt.Errorf("get system storage policy: %w", err)
	}

	return p.unmarshalPolicy(payload)
}

func (p *storagePolicyProvider) GetDefaultPolicy() (layer.PlacementPolicy, error) {
	payload, err := unwrap.Bytes(
		p.invoker().Call(p.contractHash, "getDefaultPolicy"),
	)

	if err != nil {
		return layer.PlacementPolicy{}, fmt.Errorf("get default storage policy: %w", err)
	}

	if len(payload) == 0 {
		return layer.PlacementPolicy{}, models.ErrNotFound
	}

	return p.unmarshalPolicy(payload)
}

func (p *storagePolicyProvider) unmarshalPolicy(payload []byte) (layer.PlacementPolicy, error) {
	var (
		policy layer.PlacementPolicy
		pp     netmap.PlacementPolicy
	)

	if err := json.Unmarshal(payload, &policy); err != nil {
		return layer.PlacementPolicy{}, fmt.Errorf("unmarshal placement policy: %w", err)
	}

	switch policy.Version {
	case layer.PlacementPolicyV1:
		return policy, nil
	default:
		if err := pp.UnmarshalJSON(payload); err != nil {
			return layer.PlacementPolicy{}, fmt.Errorf("unmarshal placement policy: %w", err)
		}

		policy.Placement = pp
		policy.Version = layer.PlacementPolicyV1
	}

	return policy, nil
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
		cl.Close()
		return nil, fmt.Errorf("init: %w", err)
	}

	return cl, nil
}

func (p *noOpStoragePolicyProvider) GetPlacementPolicy(_ util.Uint160, _ string) (layer.PlacementPolicy, error) {
	return layer.PlacementPolicy{}, models.ErrNotFound
}

func (p *noOpStoragePolicyProvider) GetDefaultPolicy() (layer.PlacementPolicy, error) {
	return layer.PlacementPolicy{}, models.ErrNotFound
}
