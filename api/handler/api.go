package handler

import (
	"errors"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"go.uber.org/zap"
)

type (
	handler struct {
		log         *zap.Logger
		obj         layer.Client
		notificator Notificator
		cfg         *Config
	}

	Notificator interface {
		SendNotifications(topics map[string]string, p *SendNotificationParams) error
		SendTestNotification(topic, bucketName, requestID, HostID string) error
	}

	// Config contains data which handler needs to keep.
	Config struct {
		DefaultPolicy      *netmap.PlacementPolicy
		DefaultMaxAge      int
		NotificatorEnabled bool
	}
)

// DefaultPolicy is a default policy of placing containers in NeoFS if it's not set at the request.
const DefaultPolicy = "REP 3"

var _ api.Handler = (*handler)(nil)

// New creates new api.Handler using given logger and client.
func New(log *zap.Logger, obj layer.Client, notificator Notificator, cfg *Config) (api.Handler, error) {
	switch {
	case obj == nil:
		return nil, errors.New("empty NeoFS Object Layer")
	case log == nil:
		return nil, errors.New("empty logger")
	}

	if cfg.NotificatorEnabled && notificator == nil {
		return nil, errors.New("empty notificator")
	}

	return &handler{
		log:         log,
		obj:         obj,
		cfg:         cfg,
		notificator: notificator,
	}, nil
}
