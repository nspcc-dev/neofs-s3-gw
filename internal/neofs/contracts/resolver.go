package contracts

import (
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

type (
	NNSResolver struct {
		contractReader *rpcNNS.ContractReader
	}

	NoOpNNSResolver struct {
	}
)

func NewNNSResolver(contractReader *rpcNNS.ContractReader) *NNSResolver {
	return &NNSResolver{contractReader: contractReader}
}

func (r *NNSResolver) HasUser(name string, userID user.ID) (bool, error) {
	return r.contractReader.HasNeoRecord(name, userID.ScriptHash())
}

func NewNoOpNNSResolver() *NNSResolver {
	return &NNSResolver{}
}

func (r *NoOpNNSResolver) HasUser(_ string, _ user.ID) (bool, error) {
	return false, nil
}
