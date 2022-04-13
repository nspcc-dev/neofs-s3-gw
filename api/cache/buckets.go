package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
)

// BucketCache contains cache with objects and the lifetime of cache entries.
type BucketCache struct {
	cache gcache.Cache
}

const (
	// DefaultBucketCacheSize is a default maximum number of entries in cache.
	DefaultBucketCacheSize = 1e3
	// DefaultBucketCacheLifetime is a default lifetime of entries in cache.
	DefaultBucketCacheLifetime = time.Minute
)

// DefaultBucketConfig returns new default cache expiration values.
func DefaultBucketConfig() *Config {
	return &Config{Size: DefaultBucketCacheSize, Lifetime: DefaultBucketCacheLifetime}
}

// NewBucketCache creates an object of BucketCache.
func NewBucketCache(config *Config) *BucketCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	return &BucketCache{cache: gc}
}

// Get returns a cached object.
func (o *BucketCache) Get(key string) *data.BucketInfo {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.BucketInfo)
	if !ok {
		return nil
	}

	return result
}

// Put puts an object to cache.
func (o *BucketCache) Put(bkt *data.BucketInfo) error {
	return o.cache.Set(bkt.Name, bkt)
}

// Delete deletes an object from cache.
func (o *BucketCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
