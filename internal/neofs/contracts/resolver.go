package contracts

import (
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

type (
	// NNSResolver resolves NNS names to check user ownership via NeoFS NNS contract.
	NNSResolver struct {
		contractReader *rpcNNS.ContractReader
	}

	// NoOpNNSResolver is a no-op implementation of NNS resolver that always returns false.
	NoOpNNSResolver struct {
	}
)

// NewNNSResolver creates an NNSResolver backed by the given NNS contract reader.
func NewNNSResolver(contractReader *rpcNNS.ContractReader) *NNSResolver {
	return &NNSResolver{contractReader: contractReader}
}

// HasUser checks whether the given user ID has a Neo record under the specified NNS name.
func (r *NNSResolver) HasUser(name string, userID user.ID) (bool, error) {
	return r.contractReader.HasNeoRecord(name, userID.ScriptHash())
}

// NewNoOpNNSResolver creates an NNSResolver with no contract reader that always denies access.
func NewNoOpNNSResolver() *NNSResolver {
	return &NNSResolver{}
}

// HasUser always returns false; it is a no-op implementation.
func (r *NoOpNNSResolver) HasUser(_ string, _ user.ID) (bool, error) {
	return false, nil
}
