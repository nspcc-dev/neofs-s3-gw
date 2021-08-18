package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

// HeadObjectsCache provides interface for lru cache for objects.
type HeadObjectsCache interface {
	Get(key string) *object.Address
	Put(key string, address *object.Address) error
	Delete(key string) bool
}

type (
	// HeadObjectCache contains cache with objects and lifetime of cache entries.
	HeadObjectCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// NewHeadObject creates an object of ObjectHeadersCache.
func NewHeadObject(cacheSize int, lifetime time.Duration) *HeadObjectCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &HeadObjectCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *HeadObjectCache) Get(key string) *object.Address {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*object.Address)
	if !ok {
		return nil
	}

	return result
}

// Put puts an object to cache.
func (o *HeadObjectCache) Put(key string, address *object.Address) error {
	return o.cache.SetWithExpire(key, address, o.lifetime)
}

// Delete deletes an object from cache.
func (o *HeadObjectCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
