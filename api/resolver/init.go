package resolver

import (
	"context"
	"fmt"
	"sync"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/nspcc-dev/neofs-s3-gw/internal/fschain"
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
func (r *Container) ResolveCID(ctx context.Context, name, namespace string) (cid.ID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.resolver.ResolveCID(ctx, name, namespace)
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
// It returns an error if no endpoint is available to infer NNS contract hash.
// Unavailable endpoints are used once they become available.
func NewResolver(ctx context.Context, endpoints []string) (*NNSResolver, error) {
	clients, err := fschain.NewClients(ctx, endpoints)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: %w", err)
	}

	var inferNNSHash = func(cl *rpcclient.Client) (util.Uint160, error) {
		return nns.InferHash(cl)
	}

	nnsHash, err := fschain.FirstSuccessful(clients, inferNNSHash)
	if err != nil {
		fschain.CloseClients(clients)
		return nil, fmt.Errorf("nns hash: %w", err)
	}

	var readers = make([]*nns.ContractReader, 0, len(clients))
	for _, cl := range clients {
		readers = append(readers, nns.NewReader(invoker.New(cl, nil), nnsHash))
	}

	return NewNNSResolver(readers), nil
}
