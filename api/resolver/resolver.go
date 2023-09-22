package resolver

import (
	"context"
	"errors"
	"fmt"

	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
)

const defaultZone = "container"

var (
	// ErrNotFound shows the container not found by name.
	ErrNotFound = errors.New("not found")
)

// Resolver allows to map container ID by container name.
type Resolver interface {
	Resolve(ctx context.Context, containerName string) (cid.ID, error)
}

// NNSResolver allows to resolve container id by its name.
type NNSResolver struct {
	reader *rpcNNS.ContractReader
}

// NewNNSResolver is a constructor for the NNSResolver.
func NewNNSResolver(reader *rpcNNS.ContractReader) *NNSResolver {
	return &NNSResolver{reader: reader}
}

// Resolve looks up the container id by its name via NNS contract.
func (r *NNSResolver) Resolve(_ context.Context, name string) (cid.ID, error) {
	var result cid.ID

	items, err := r.reader.GetRecords(nnsContainerDomain(name), rpcNNS.TXT)
	if err != nil {
		return result, fmt.Errorf("nns get: %w", err)
	}

	if len(items) == 0 {
		return result, ErrNotFound
	}

	if err = result.DecodeString(items[0]); err != nil {
		return result, fmt.Errorf("id: %w", err)
	}

	return result, nil
}

func nnsContainerDomain(name string) string {
	return fmt.Sprintf("%s.%s", name, defaultZone)
}
