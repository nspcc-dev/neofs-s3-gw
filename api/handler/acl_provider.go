package handler

import (
	"context"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"go.uber.org/zap"
)

type (
	// NeoFSEACLGetter gets actual bucket EACL table.
	NeoFSEACLGetter interface {
		ContainerEACL(ctx context.Context, id cid.ID, prm client.PrmContainerEACL) (eacl.Table, error)
	}

	// ACLCachedProvider is a cached provider for bucket ACL state.
	ACLCachedProvider struct {
		cache  *cache.BucketACLStateCache
		getter NeoFSEACLGetter
		logger *zap.Logger
	}
)

// NewACLCachedProvider is a constructor for ACLCachedProvider.
func NewACLCachedProvider(logger *zap.Logger, getter NeoFSEACLGetter, cache *cache.BucketACLStateCache) *ACLCachedProvider {
	return &ACLCachedProvider{
		cache:  cache,
		getter: getter,
		logger: logger,
	}
}

// GetState returns actual ACL state for bucket.
// Implements ACLStateProvider.
func (a *ACLCachedProvider) GetState(ctx context.Context, idCnr cid.ID) (data.BucketACLState, error) {
	v := a.cache.Get(idCnr)
	if v != nil {
		return *v, nil
	}

	table, err := a.getter.ContainerEACL(ctx, idCnr, client.PrmContainerEACL{})
	if err != nil {
		return data.BucketACLEnabled, fmt.Errorf("get %q eacl: %w", idCnr.String(), err)
	}

	var state data.BucketACLState

	if err = checkACLRestrictions(&table); err != nil {
		if errors.Is(err, errBucketOwnerEnforced) {
			state = data.BucketACLBucketOwnerEnforced
		}
	}

	if err = a.cache.Put(idCnr, state); err != nil {
		a.logger.Warn("couldn't put bucket acl state into cache",
			zap.Stringer("cid", idCnr),
			zap.Error(err))
	}

	return state, nil
}
