package resolver

import (
	"context"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/rpc/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/resolver"
)

const (
	NNSResolver = "nns"
	DNSResolver = "dns"

	networkSystemDNSParam = "SystemDNS"
)

type Config struct {
	Pool pool.Pool
	RPC  *client.Client
}

type BucketResolver struct {
	Name    string
	resolve func(context.Context, string) (*cid.ID, error)

	next *BucketResolver
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
		return NewDNSResolver(cfg.Pool, next)
	case NNSResolver:
		return NewNNSResolver(cfg.RPC, next)
	default:
		return nil, fmt.Errorf("unknown resolver: %s", name)
	}
}

func NewDNSResolver(p pool.Pool, next *BucketResolver) (*BucketResolver, error) {
	if p == nil {
		return nil, fmt.Errorf("pool must not be nil for DNS resolver")
	}

	resolveFunc := func(ctx context.Context, name string) (*cid.ID, error) {
		conn, _, err := p.Connection()
		if err != nil {
			return nil, err
		}

		networkInfoRes, err := conn.NetworkInfo(ctx)
		if err == nil {
			err = apistatus.ErrFromStatus(networkInfoRes.Status())
		}
		if err != nil {
			return nil, err
		}

		networkInfo := networkInfoRes.Info()

		var domain string
		networkInfo.NetworkConfig().IterateParameters(func(parameter *netmap.NetworkParameter) bool {
			if string(parameter.Key()) == networkSystemDNSParam {
				domain = string(parameter.Value())
				return true
			}
			return false
		})

		if domain == "" {
			return nil, fmt.Errorf("couldn't resolve container '%s': not found", name)
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
