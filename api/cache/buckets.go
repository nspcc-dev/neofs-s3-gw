package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api"
)

type (
	// BucketCache provides interface for lru cache for objects.
	BucketCache interface {
		Get(key string) *api.BucketInfo
		Put(bkt *api.BucketInfo) error
		Delete(key string) bool
	}

	// GetBucketCache contains cache with objects and lifetime of cache entries.
	GetBucketCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// NewBucketCache creates an object of BucketCache.
func NewBucketCache(cacheSize int, lifetime time.Duration) *GetBucketCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &GetBucketCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *GetBucketCache) Get(key string) *api.BucketInfo {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*api.BucketInfo)
	if !ok {
		return nil
	}

	return result
}

// Put puts an object to cache.
func (o *GetBucketCache) Put(bkt *api.BucketInfo) error {
	return o.cache.SetWithExpire(bkt.Name, bkt, o.lifetime)
}

// Delete deletes an object from cache.
func (o *GetBucketCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
