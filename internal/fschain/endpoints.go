package fschain

import (
	"context"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/util"
)

// NewClients creates RPC clients for all endpoints. Clients don't connect to
// endpoints on creation, so unavailable endpoints are used once they become available.
func NewClients(ctx context.Context, endpoints []string) ([]*rpcclient.Client, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("endpoints must be set")
	}

	var clients = make([]*rpcclient.Client, 0, len(endpoints))
	for _, endpoint := range endpoints {
		cl, err := rpcclient.New(ctx, endpoint, rpcclient.Options{})
		if err != nil {
			CloseClients(clients)
			return nil, fmt.Errorf("%q: %w", endpoint, err)
		}

		clients = append(clients, cl)
	}

	return clients, nil
}

// FirstSuccessful returns the contract hash from the first client f succeeds for.
//
// It returns an error if f fails for all clients.
func FirstSuccessful(clients []*rpcclient.Client, f func(*rpcclient.Client) (util.Uint160, error)) (util.Uint160, error) {
	var errs []error

	for _, cl := range clients {
		res, err := f(cl)
		if err == nil {
			return res, nil
		}

		errs = append(errs, fmt.Errorf("%q: %w", cl.Endpoint(), err))
	}

	return util.Uint160{}, fmt.Errorf("all RPC endpoints failed: %w", errors.Join(errs...))
}

// CloseClients closes all clients.
func CloseClients(clients []*rpcclient.Client) {
	for _, cl := range clients {
		cl.Close()
	}
}
