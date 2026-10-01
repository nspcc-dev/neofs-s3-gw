package neofs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/nspcc-dev/neo-go/pkg/core/state"
	"github.com/nspcc-dev/neo-go/pkg/neorpc"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/invoker"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neofs-contract/rpc/netmap"
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
		notifyChan     chan *state.ContainedNotificationEvent
		netMapContract util.Uint160
		endpoints      []string

		clientMu *sync.Mutex
		client   *rpcclient.WSClient

		netmapVersion atomic.Uint64
		netmapChanged chan struct{}
	}
)

var (
	eventName       = "NewEpoch"
	netmapEventName = "NewNetmap"
)

// NewEpochListener is a constructor for EpochListener.
func NewEpochListener(endpoints []string, log *zap.Logger, netMapContract util.Uint160) *EpochListener {
	return &EpochListener{
		log:            log.With(zap.String("service", "epoch_notifications")),
		endpoints:      endpoints,
		netMapContract: netMapContract,
		clientMu:       &sync.Mutex{},
	}
}

// WatchNetmap enables network map tracking starting from the given version.
// It must be called before [EpochListener.ListenNotifications].
func (l *EpochListener) WatchNetmap(version uint64) <-chan struct{} {
	l.netmapVersion.Store(version)
	l.netmapChanged = make(chan struct{}, 1)

	return l.netmapChanged
}

// CurrentEpoch returns actual epoch.
//
// CurrentEpoch implements [EpochGetter].
func (l *EpochListener) CurrentEpoch() uint64 {
	return l.epoch.Load()
}

func (l *EpochListener) forceGetEpoch() error {
	l.clientMu.Lock()
	// The client should be available until the function is done.
	defer l.clientMu.Unlock()
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

		l.clientMu.Lock()
		l.client = cl
		l.clientMu.Unlock()

		l.log.Info("ws connected", zap.String("endpoint", endpoint))

		return nil
	}

	return errors.New("all hosts failed to connect")
}

// ListenNotifications start listening notifications. Reconnects in case of disconnect.
func (l *EpochListener) ListenNotifications(ctx context.Context) {
	go func() {
		bo := backoff.NewExponentialBackOff()

		for {
			select {
			case <-ctx.Done():
				l.log.Info("stopping. Context done")
				return
			default:
			}

			if err := l.connect(ctx); err != nil {
				l.log.Error("connection failed", zap.Error(err))
				time.Sleep(bo.NextBackOff())
				continue
			}

			bo.Reset()

			l.notifyChan = make(chan *state.ContainedNotificationEvent)

			id, err := l.client.ReceiveExecutionNotifications(&neorpc.NotificationFilter{Contract: &l.netMapContract}, l.notifyChan)
			if err != nil {
				l.log.Info("receive execution notifications failed", zap.Error(err))

				l.clientMu.Lock()
				_ = l.client.Unsubscribe(id)
				l.client.Close()
				l.clientMu.Unlock()
				continue
			}

			go func() {
				if err = l.forceGetEpoch(); err != nil {
					l.log.Info("force get epoch", zap.Error(err))

					l.clientMu.Lock()
					_ = l.client.Unsubscribe(id)
					l.client.Close()
					l.clientMu.Unlock()
				}
			}()

			if l.netmapChanged != nil {
				go l.forceGetNetmapVersion()
			}

			l.readNotifications(ctx)
		}
	}()
}

func (l *EpochListener) readNotifications(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			l.log.Info("stopping. Context done")
			return
		case notification, ok := <-l.notifyChan:
			if !ok {
				return
			}

			switch notification.Name {
			case eventName:
				var newEpochEvent netmap.NewEpochEvent
				if err := newEpochEvent.FromStackItem(notification.Item); err != nil {
					l.log.Error("failed to parse NewEpoch event", zap.Error(err))
					continue
				}

				l.updateEpoch(newEpochEvent.Epoch.Uint64())
			case netmapEventName:
				if l.netmapChanged == nil {
					continue
				}

				var newNetmapEvent netmap.NewNetmapEvent
				if err := newNetmapEvent.FromStackItem(notification.Item); err != nil {
					l.log.Error("failed to parse NewNetmap event", zap.Error(err))
					continue
				}

				l.updateNetmapVersion(newNetmapEvent.Version.Uint64())
			}
		}
	}
}

func (l *EpochListener) updateEpoch(e uint64) {
	if e > l.epoch.Load() {
		l.epoch.Store(e)
		l.log.Info("epoch update", zap.Uint64("epoch", e))
	}
}

func (l *EpochListener) forceGetNetmapVersion() {
	l.clientMu.Lock()
	version, err := netmap.NewReader(invoker.New(l.client, nil), l.netMapContract).NetworkMapVersion()
	l.clientMu.Unlock()

	if err != nil {
		l.log.Warn("failed to get network map version", zap.Error(err))
		return
	}

	l.updateNetmapVersion(version.Uint64())
}

func (l *EpochListener) updateNetmapVersion(v uint64) {
	for {
		cur := l.netmapVersion.Load()
		if v <= cur {
			return
		}

		if l.netmapVersion.CompareAndSwap(cur, v) {
			break
		}
	}

	l.log.Info("network map update", zap.Uint64("version", v))

	select {
	case l.netmapChanged <- struct{}{}:
	default:
	}
}
