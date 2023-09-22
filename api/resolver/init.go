package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
)

const (
	nnsContract = int32(1)
)

// Container is a wrapper for the [Resolver]. It allows to update resolvers in runtime, without service restarting.
//
// The Container should be used like regular [Resolver].
type Container struct {
	mu       sync.RWMutex
	resolver Resolver
}

// Resolve looks up the container id by its name via NNS contract.
// The method calls inline resolver.
func (r *Container) Resolve(ctx context.Context, name string) (cid.ID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.resolver.Resolve(ctx, name)
}

// UpdateResolvers allows to update resolver in runtime. Resolvers will be created from scratch.
func (r *Container) UpdateResolvers(ctx context.Context, endpoint string) error {
	newResolver, err := NewResolver(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("resolver reinit: %w", err)
	}

	r.mu.Lock()
	r.resolver = newResolver
	r.mu.Unlock()

	return nil
}

// NewContainer is a constructor for the [Container].
func NewContainer(ctx context.Context, endpoint string) (*Container, error) {
	newResolver, err := NewResolver(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolver reinit: %w", err)
	}

	return &Container{
		resolver: newResolver,
	}, nil
}

// NewResolver returns resolver depending on corresponding endpoint.
//
// If endpoint is empty, error will be returned.
func NewResolver(ctx context.Context, endpoint string) (Resolver, error) {
	if endpoint == "" {
		return nil, errors.New("endpoint must be set")
	}

	cl, err := rpcClient(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: %w", err)
	}

	nnsHash, err := systemContractHash(cl, nnsContract)
	if err != nil {
		return nil, fmt.Errorf("nns contract: %w", err)
	}

	inv := invoker.New(cl, nil)
	nnsReader := rpcNNS.NewReader(inv, nnsHash)
	return NewNNSResolver(nnsReader), nil
}

func systemContractHash(cl *rpcclient.Client, id int32) (util.Uint160, error) {
	c, err := cl.GetContractStateByID(id)
	if err != nil {
		return util.Uint160{}, fmt.Errorf("GetContractStateByID [%d]: %w", id, err)
	}

	return c.Hash, nil
}

func rpcClient(ctx context.Context, endpoint string) (*rpcclient.Client, error) {
	cl, err := rpcclient.New(ctx, endpoint, rpcclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("new: %w", err)
	}

	err = cl.Init()
	if err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}

	return cl, nil
}
