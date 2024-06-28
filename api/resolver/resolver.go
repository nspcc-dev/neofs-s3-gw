package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
)

const defaultZone = "container"

var (
	// ErrNotFound shows the container not found by name.
	ErrNotFound = errors.New("not found")
)

// NNSResolver allows to resolve container id by its name.
type NNSResolver struct {
	mu      *sync.Mutex
	next    uint32
	readers []*rpcNNS.ContractReader
}

// NewNNSResolver is a constructor for the NNSResolver.
func NewNNSResolver(readers []*rpcNNS.ContractReader) *NNSResolver {
	return &NNSResolver{readers: readers, mu: &sync.Mutex{}}
}

// ResolveCID looks up the container id by its name via NNS contract.
func (r *NNSResolver) ResolveCID(_ context.Context, name string) (cid.ID, error) {
	var result cid.ID

	items, err := r.reader().GetRecords(nnsContainerDomain(name), rpcNNS.TXT)
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

func (r *NNSResolver) index() int {
	r.mu.Lock()

	r.next++
	index := (int(r.next) - 1) % len(r.readers)

	if int(r.next) >= len(r.readers) {
		r.next = 0
	}

	r.mu.Unlock()

	return index
}

func (r *NNSResolver) reader() *rpcNNS.ContractReader {
	return r.readers[r.index()]
}

func nnsContainerDomain(name string) string {
	return fmt.Sprintf("%s.%s", name, defaultZone)
}
