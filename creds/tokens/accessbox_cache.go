package tokens

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
)

const (
	// DefaultCacheSize is a default maximum number of entries in cache.
	DefaultCacheSize = 100
	// DefaultCacheLifetime is a default lifetime of entries in  cache.
	DefaultCacheLifetime = 10 * time.Minute
)

// CacheConfig stores expiration params for cache.
type CacheConfig struct {
	Size     int
	Lifetime time.Duration
}

// DefaultCacheConfig return new default cache expiration values.
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{Size: DefaultCacheSize, Lifetime: DefaultCacheLifetime}
}

// AccessBoxCache stores access box by its address.
type AccessBoxCache struct {
	cache gcache.Cache
}

// NewAccessBoxCache creates an object of BucketCache.
func NewAccessBoxCache(config *CacheConfig) *AccessBoxCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()

	return &AccessBoxCache{cache: gc}
}

// Get returns cached object.
func (o *AccessBoxCache) Get(address *object.Address) *accessbox.Box {
	entry, err := o.cache.Get(address.String())
	if err != nil {
		return nil
	}

	result, ok := entry.(*accessbox.Box)
	if !ok {
		return nil
	}

	return result
}

// Put stores an object to cache.
func (o *AccessBoxCache) Put(address *object.Address, box *accessbox.Box) error {
	return o.cache.Set(address.String(), box)
}
