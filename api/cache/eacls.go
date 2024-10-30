package cache

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"go.uber.org/zap"
)

type (
	// BucketACLStateCache contains cache with bucket ACL state.
	BucketACLStateCache struct {
		cache  gcache.Cache
		logger *zap.Logger
	}
)

const (
	// DefaultEACLCacheSize is a default maximum number of entries in cache.
	DefaultEACLCacheSize = 1e3
	// DefaultEACLCacheLifetime is a default lifetime of entries in cache.
	DefaultEACLCacheLifetime = time.Minute
)

// DefaultBucketACLStateCacheConfig returns new default cache expiration values.
func DefaultBucketACLStateCacheConfig(logger *zap.Logger) *Config {
	return &Config{
		Size:     DefaultEACLCacheSize,
		Lifetime: DefaultEACLCacheLifetime,
		Logger:   logger,
	}
}

// NewEACLCache creates an object of BucketACLStateCache.
func NewEACLCache(config *Config) *BucketACLStateCache {
	return &BucketACLStateCache{
		cache:  gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build(),
		logger: config.Logger}
}

// Get returns a cached state.
func (o *BucketACLStateCache) Get(id cid.ID) *data.BucketACLState {
	entry, err := o.cache.Get(id.String())
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.BucketACLState)
	if !ok {
		o.logger.Warn("invalid cache entry type",
			zap.String("actual", fmt.Sprintf("%T", entry)),
			zap.String("expected", fmt.Sprintf("%T", result)),
		)
		return nil
	}

	return result
}

// Put puts a state to cache.
func (o *BucketACLStateCache) Put(id cid.ID, v data.BucketACLState) error {
	return o.cache.Set(id.String(), &v)
}

// Delete deletes a state from cache.
func (o *BucketACLStateCache) Delete(id cid.ID) bool {
	return o.cache.Remove(id.String())
}
