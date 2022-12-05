package handler

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"go.uber.org/zap"
)

type (
	handler struct {
		log         *zap.Logger
		cfg         *Config
		neoFS       NeoFS
		notificator Notificator
		resolver    BucketResolver
		cache       *Cache
		treeService TreeService
	}

	// AnonymousKey contains data for anonymous requests.
	AnonymousKey struct {
		Key *keys.PrivateKey
	}

	Notificator interface {
		SendNotifications(topics map[string]string, p *SendNotificationParams) error
		SendTestNotification(topic, bucketName, requestID, HostID string, now time.Time) error

		Subscribe(context.Context, string, MsgHandler) error
		Listen(context.Context)
	}

	MsgHandler interface {
		HandleMessage(context.Context, *nats.Msg) error
	}

	BucketResolver interface {
		Resolve(ctx context.Context, name string) (cid.ID, error)
	}

	// Config contains data which handler needs to keep.
	Config struct {
		Policy             PlacementPolicy
		DefaultMaxAge      int
		NotificatorEnabled bool
		CopiesNumber       uint32
		AnonKey            AnonymousKey
		Cache              *CachesConfig
		Resolver           BucketResolver
		TreeService        TreeService
		NeoFS              NeoFS
	}

	PlacementPolicy interface {
		Default() netmap.PlacementPolicy
		Get(string) (netmap.PlacementPolicy, bool)
	}
)

const (
	// DefaultPolicy is a default policy of placing containers in NeoFS if it's not set at the request.
	DefaultPolicy = "REP 3"
	// DefaultCopiesNumber is a default number of object copies that is enough to consider put successful if it's not set in config.
	DefaultCopiesNumber uint32 = 0
)

var _ api.Handler = (*handler)(nil)

// New creates new api.Handler using given logger and client.
func New(ctx context.Context, log *zap.Logger, notificator Notificator, cfg *Config) (api.Handler, error) {
	switch {
	case log == nil:
		return nil, errors.New("empty logger")
	}

	if !cfg.NotificatorEnabled {
		log.Warn("notificator is disabled, s3 won't produce notification events")
	} else if notificator == nil {
		return nil, errors.New("empty notificator")
	}

	h := &handler{
		log:         log,
		cfg:         cfg,
		notificator: notificator,
		neoFS:       cfg.NeoFS,
		resolver:    cfg.Resolver,
		cache:       NewCache(cfg.Cache),
		treeService: cfg.TreeService,
	}

	if cfg.NotificatorEnabled {
		h.notificator.Listen(ctx)
	}

	return h, nil
}
