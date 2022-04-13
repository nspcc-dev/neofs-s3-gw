package resolver

import (
	"context"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/rpc/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/resolver"
)

const (
	NNSResolver = "nns"
	DNSResolver = "dns"
)

// NeoFS represents virtual connection to the NeoFS network.
type NeoFS interface {
	// SystemDNS reads system DNS network parameters of the NeoFS.
	//
	// It returns exactly on non-zero value. It returns any error encountered
	// which prevented the parameter from being read.
	SystemDNS(context.Context) (string, error)
}

type Config struct {
	NeoFS NeoFS
	RPC   *client.Client
}

type BucketResolver struct {
	Name    string
	resolve func(context.Context, string) (*cid.ID, error)

	next *BucketResolver
}

func (r *BucketResolver) SetResolveFunc(fn func(context.Context, string) (*cid.ID, error)) {
	r.resolve = fn
}

func (r *BucketResolver) Resolve(ctx context.Context, name string) (*cid.ID, error) {
	cnrID, err := r.resolve(ctx, name)
	if err != nil {
		if r.next != nil {
			return r.next.Resolve(ctx, name)
		}
		return nil, err
	}
	return cnrID, err
}

func NewResolver(order []string, cfg *Config) (*BucketResolver, error) {
	if len(order) == 0 {
		return nil, fmt.Errorf("resolving order must not be empty")
	}

	bucketResolver, err := newResolver(order[len(order)-1], cfg, nil)
	if err != nil {
		return nil, err
	}

	for i := len(order) - 2; i >= 0; i-- {
		resolverName := order[i]
		next := bucketResolver

		bucketResolver, err = newResolver(resolverName, cfg, next)
		if err != nil {
			return nil, err
		}
	}

	return bucketResolver, nil
}

func newResolver(name string, cfg *Config, next *BucketResolver) (*BucketResolver, error) {
	switch name {
	case DNSResolver:
		return NewDNSResolver(cfg.NeoFS, next)
	case NNSResolver:
		return NewNNSResolver(cfg.RPC, next)
	default:
		return nil, fmt.Errorf("unknown resolver: %s", name)
	}
}

func NewDNSResolver(neoFS NeoFS, next *BucketResolver) (*BucketResolver, error) {
	if neoFS == nil {
		return nil, fmt.Errorf("pool must not be nil for DNS resolver")
	}

	resolveFunc := func(ctx context.Context, name string) (*cid.ID, error) {
		domain, err := neoFS.SystemDNS(ctx)
		if err != nil {
			return nil, fmt.Errorf("read system DNS parameter of the NeoFS: %w", err)
		}

		domain = name + "." + domain
		cnrID, err := resolver.ResolveContainerDomainName(domain)
		if err != nil {
			return nil, fmt.Errorf("couldn't resolve container '%s' as '%s': %w", name, domain, err)
		}
		return cnrID, nil
	}

	return &BucketResolver{
		Name: DNSResolver,

		resolve: resolveFunc,
		next:    next,
	}, nil
}

func NewNNSResolver(rpc *client.Client, next *BucketResolver) (*BucketResolver, error) {
	if rpc == nil {
		return nil, fmt.Errorf("rpc client must not be nil for NNS resolver")
	}

	nnsRPCResolver, err := resolver.NewNNSResolver(rpc)
	if err != nil {
		return nil, err
	}

	resolveFunc := func(_ context.Context, name string) (*cid.ID, error) {
		cnrID, err := nnsRPCResolver.ResolveContainerName(name)
		if err != nil {
			return nil, fmt.Errorf("couldn't resolve container '%s': %w", name, err)
		}
		return cnrID, nil
	}

	return &BucketResolver{
		Name: NNSResolver,

		resolve: resolveFunc,
		next:    next,
	}, nil
}
