package handler

import (
	"context"
	"errors"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
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
		SendTestNotification(topic, bucketName, requestID, HostID string, now time.Time) error
	}

	// Config contains data which handler needs to keep.
	Config struct {
		Policy                  PlacementPolicy
		PlacementPolicyProvider PlacementPolicyProvider
		DefaultMaxAge           int
		NotificatorEnabled      bool
		CopiesNumber            uint32
		MaxDeletePerRequest     int
		ContainerMetadataPolicy string
	}

	PlacementPolicy interface {
		Default() netmap.PlacementPolicy
		Get(string) (netmap.PlacementPolicy, bool)
	}

	// PlacementPolicyProvider takes placement policy from contract.
	PlacementPolicyProvider interface {
		// GetPlacementPolicy get policy by name.
		// Returns [models.ErrNotFound] if policy not found.
		GetPlacementPolicy(userAddr util.Uint160, policyName string) (*layer.PlacementPolicy, error)
	}

	// ACLStateProvider get bucket ACL state.
	ACLStateProvider interface {
		GetState(ctx context.Context, idCnr cid.ID) (data.BucketACLState, error)
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
func New(log *zap.Logger, obj layer.Client, notificator Notificator, cfg *Config) (api.Handler, error) {
	switch {
	case obj == nil:
		return nil, errors.New("empty NeoFS Object Layer")
	case log == nil:
		return nil, errors.New("empty logger")
	}

	if !cfg.NotificatorEnabled {
		log.Warn("notificator is disabled, s3 won't produce notification events")
	} else if notificator == nil {
		return nil, errors.New("empty notificator")
	}

	return &handler{
		log:         log,
		obj:         obj,
		cfg:         cfg,
		notificator: notificator,
	}, nil
}
