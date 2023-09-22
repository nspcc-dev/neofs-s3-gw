package neofs

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"go.uber.org/zap"
)

type (
	// NetworkInfoGetter represents provider to get actual [netmap.NetworkInfo].
	NetworkInfoGetter interface {
		NetworkInfo(ctx context.Context, prm client.PrmNetworkInfo) (netmap.NetworkInfo, error)
	}

	// EpochGetter represents provider to get actual NeoFS epoch.
	EpochGetter interface {
		CurrentEpoch() uint64
	}

	// PeriodicGetter implements [EpochGetter].
	PeriodicGetter struct {
		logger    *zap.Logger
		netGetter NetworkInfoGetter
		epoch     atomic.Uint64
		timeOut   time.Duration
	}
)

// NewPeriodicGetter is a constructor to [PeriodicGetter].
func NewPeriodicGetter(ctx context.Context, initialEpoch uint64, timeOut time.Duration, netGetter NetworkInfoGetter, logger *zap.Logger) *PeriodicGetter {
	getter := &PeriodicGetter{
		timeOut:   timeOut,
		netGetter: netGetter,
		logger:    logger,
	}

	getter.epoch.Store(initialEpoch)

	go getter.update(ctx)

	return getter
}

// CurrentEpoch returns actual epoch.
//
// CurrentEpoch implements [EpochGetter].
func (g *PeriodicGetter) CurrentEpoch() uint64 {
	return g.epoch.Load()
}

func (g *PeriodicGetter) update(ctx context.Context) {
	tm := time.NewTicker(g.timeOut)

	for {
		select {
		case <-ctx.Done():
			tm.Stop()
			return
		case <-tm.C:
			ni, err := g.netGetter.NetworkInfo(ctx, client.PrmNetworkInfo{})
			if err != nil {
				g.logger.Error("periodicGetter: networkInfo", zap.Error(err))
				continue
			}

			g.logger.Info("periodicGetter", zap.Uint64("epoch", ni.CurrentEpoch()))
			g.epoch.Store(ni.CurrentEpoch())
		}
	}
}
