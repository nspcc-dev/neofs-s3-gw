package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neofs-contract/rpc/nns"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
)

// Container is a wrapper for the [NNSResolver]. It allows to update resolvers in runtime, without service restarting.
//
// The Container should be used like regular [NNSResolver].
type Container struct {
	mu       sync.RWMutex
	resolver *NNSResolver
}

// ResolveCID looks up the container id by its name via NNS contract.
// The method calls inline resolver.
func (r *Container) ResolveCID(ctx context.Context, name string) (cid.ID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.resolver.ResolveCID(ctx, name)
}

// UpdateResolvers allows to update resolver in runtime. Resolvers will be created from scratch.
func (r *Container) UpdateResolvers(ctx context.Context, endpoints []string) error {
	newResolver, err := NewResolver(ctx, endpoints)
	if err != nil {
		return fmt.Errorf("resolver reinit: %w", err)
	}

	r.mu.Lock()
	r.resolver = newResolver
	r.mu.Unlock()

	return nil
}

// NewContainer is a constructor for the [Container].
func NewContainer(ctx context.Context, endpoints []string) (*Container, error) {
	newResolver, err := NewResolver(ctx, endpoints)
	if err != nil {
		return nil, fmt.Errorf("resolver reinit: %w", err)
	}

	return &Container{
		resolver: newResolver,
	}, nil
}

// NewResolver returns resolver depending on corresponding endpoints.
//
// If endpoint is empty, error will be returned.
func NewResolver(ctx context.Context, endpoints []string) (*NNSResolver, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("endpoints must be set")
	}

	var readers = make([]*nns.ContractReader, 0, len(endpoints))

	for _, endpoint := range endpoints {
		cl, err := rpcClient(ctx, endpoint)
		if err != nil {
			return nil, fmt.Errorf("rpcclient: %w", err)
		}

		inv := invoker.New(cl, nil)
		nnsReader, err := nns.NewInferredReader(cl, inv)
		if err != nil {
			return nil, fmt.Errorf("nns readers instantiation: %w", err)
		}

		readers = append(readers, nnsReader)
	}

	return NewNNSResolver(readers), nil
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
