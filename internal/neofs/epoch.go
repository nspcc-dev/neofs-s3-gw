package neofs

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/core/state"
	"github.com/nspcc-dev/neo-go/pkg/neorpc"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neofs-contract/rpc/netmap"
	rpcNNS "github.com/nspcc-dev/neofs-contract/rpc/nns"
	"go.uber.org/zap"
)

type (
	// EpochGetter represents provider to get actual NeoFS epoch.
	EpochGetter interface {
		CurrentEpoch() uint64
	}

	// EpochListener implements [EpochGetter].
	EpochListener struct {
		log            *zap.Logger
		epoch          atomic.Uint64
		client         *rpcclient.WSClient
		notifyChan     chan *state.ContainedNotificationEvent
		netMapContract util.Uint160
		endpoints      []string
	}
)

var (
	eventName = "NewEpoch"
)

// NewEpochListener is a constructor for EpochListener.
func NewEpochListener(endpoints []string, log *zap.Logger) *EpochListener {
	return &EpochListener{
		log:       log.With(zap.String("service", "epoch_notifications")),
		endpoints: endpoints,
	}
}

// CurrentEpoch returns actual epoch.
//
// CurrentEpoch implements [EpochGetter].
func (l *EpochListener) CurrentEpoch() uint64 {
	return l.epoch.Load()
}

func (l *EpochListener) Init(ctx context.Context) error {
	if err := l.connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	inv := invoker.New(l.client, nil)
	nnsReader, err := rpcNNS.NewInferredReader(l.client, inv)
	if err != nil {
		return fmt.Errorf("new inferred reader: %w", err)
	}

	netMapContract, err := nnsReader.ResolveFSContract(rpcNNS.NameNetmap)
	if err != nil {
		return err
	}
	l.netMapContract = netMapContract

	if err = l.forceGetEpoch(); err != nil {
		return fmt.Errorf("get initial epoch: %w", err)
	}

	return nil
}
func (l *EpochListener) forceGetEpoch() error {
	inv := invoker.New(l.client, nil)

	netMapReader := netmap.NewReader(inv, l.netMapContract)
	epoch, err := netMapReader.Epoch()
	if err != nil {
		return fmt.Errorf("failed to get actual epoch: %w", err)
	}

	l.updateEpoch(epoch.Uint64())
	return nil
}

func (l *EpochListener) connect(ctx context.Context) error {
	var (
		opts rpcclient.WSOptions
		ok   bool
	)

	for _, endpoint := range l.endpoints {
		cl, err := rpcclient.NewWS(ctx, endpoint, opts)
		if err != nil {
			l.log.Info("create ws client", zap.Error(err), zap.String("endpoint", endpoint))
			continue
		}

		if err = cl.Init(); err != nil {
			l.log.Info("ws client init", zap.Error(err), zap.String("endpoint", endpoint))
			continue
		}

		l.client = cl
		ok = true
		break
	}

	if !ok {
		return errors.New("all hosts failed to connect")
	}

	return nil
}

// ListenNotifications start listening notifications. Reconnects in case of disconnect.
func (l *EpochListener) ListenNotifications(ctx context.Context) {
	go func() {
		for {
			if err := l.connect(ctx); err != nil {
				l.log.Error("connection failed", zap.Error(err))
				time.Sleep(1 * time.Second)
				continue
			}

			if err := l.forceGetEpoch(); err != nil {
				l.log.Info("failed to get actual epoch after reconnect", zap.Error(err))
				l.client.Close()
				l.client = nil
				return
			}

			select {
			case <-ctx.Done():
				l.log.Info("stopping. Context done")
				return
			default:
			}

			l.notifyChan = make(chan *state.ContainedNotificationEvent)

			id, err := l.client.ReceiveExecutionNotifications(&neorpc.NotificationFilter{Contract: &l.netMapContract, Name: &eventName}, l.notifyChan)
			if err != nil {
				l.log.Info("receive execution notifications failed", zap.Error(err))

				_ = l.client.Unsubscribe(id)
				l.client.Close()
				l.client = nil

				continue
			}

			l.readNotifications()
		}
	}()
}

func (l *EpochListener) readNotifications() {
	for {
		notification, ok := <-l.notifyChan
		if !ok {
			break
		}

		var newEpochEvent netmap.NewEpochEvent
		if err := newEpochEvent.FromStackItem(notification.Item); err != nil {
			l.log.Error("failed to parse NewEpoch", zap.Error(err))
			continue
		}

		l.updateEpoch(newEpochEvent.Epoch.Uint64())
	}
}

func (l *EpochListener) updateEpoch(e uint64) {
	if e > l.epoch.Load() {
		l.epoch.Store(e)
		l.log.Info("epoch update", zap.Uint64("epoch", e))
	}
}
