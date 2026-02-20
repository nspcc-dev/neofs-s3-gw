package contracts

import (
	"context"
	"errors"

	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"go.uber.org/zap"
)

type (
	// ResolvedContracts contains info about resolver contracts.
	ResolvedContracts struct {
		NetMapContract    util.Uint160
		ContainerContract util.Uint160
		NNSContractReader *rpcNNS.ContractReader
	}
)

// ResolveContracts resolves contracts.
func ResolveContracts(ctx context.Context, log *zap.Logger, rpcHTTPEndpoints []string) (ResolvedContracts, error) {
	var (
		opt    rpcclient.Options
		result ResolvedContracts
	)

	log = log.Named("resolveContracts")

	for _, endpoint := range rpcHTTPEndpoints {
		cl, err := rpcclient.New(ctx, endpoint, opt)
		if err != nil {
			log.Info("could not instantiate RPC client", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}
		defer cl.Close()

		if err = cl.Init(); err != nil {
			log.Info("could not initialize RPC client", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}

		nnsReader, err := rpcNNS.NewInferredReader(cl, invoker.New(cl, nil))
		if err != nil {
			log.Info("couldn't create inferred reader", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}

		result.NNSContractReader = nnsReader

		result.NetMapContract, err = nnsReader.ResolveFSContract(rpcNNS.NameNetmap)
		if err != nil {
			log.Info("couldn't resolve netmap contract", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}
		result.ContainerContract, err = nnsReader.ResolveFSContract(rpcNNS.NameContainer)
		if err != nil {
			log.Info("couldn't resolve cotanier contract", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}

		return result, nil
	}

	return result, errors.New("could not initialize RPC client")
}
