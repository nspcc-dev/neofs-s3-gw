package cache

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"go.uber.org/zap"
)

type (
	// BucketACLCache contains cache with bucket EACL.
	BucketACLCache struct {
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

// DefaultBucketACLCacheConfig returns new default cache expiration values.
func DefaultBucketACLCacheConfig(logger *zap.Logger) *Config {
	return &Config{
		Size:     DefaultEACLCacheSize,
		Lifetime: DefaultEACLCacheLifetime,
		Logger:   logger,
	}
}

// NewEACLCache creates an object of BucketACLCache.
func NewEACLCache(config *Config) *BucketACLCache {
	return &BucketACLCache{
		cache:  gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build(),
		logger: config.Logger}
}

// Get returns a cached state.
func (o *BucketACLCache) Get(id cid.ID) *eacl.Table {
	entry, err := o.cache.Get(id.String())
	if err != nil {
		return nil
	}

	result, ok := entry.(*eacl.Table)
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
func (o *BucketACLCache) Put(id cid.ID, v *eacl.Table) error {
	return o.cache.Set(id.String(), v)
}

// Delete deletes a state from cache.
func (o *BucketACLCache) Delete(id cid.ID) bool {
	return o.cache.Remove(id.String())
}
