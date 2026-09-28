package fschain

import (
	"errors"
	"fmt"
)

// ForEachEndpoint initializes every endpoint.
//
// It returns an error if no endpoint is initialized successfully.
func ForEachEndpoint(endpoints []string, initialize func(string) error) error {
	if len(endpoints) == 0 {
		return errors.New("endpoints must be set")
	}

	var initialized int
	var errs []error

	for _, endpoint := range endpoints {
		if err := initialize(endpoint); err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", endpoint, err))
			continue
		}

		initialized++
	}

	if initialized == 0 {
		return fmt.Errorf("all RPC endpoints failed: %w", errors.Join(errs...))
	}

	return nil
}
