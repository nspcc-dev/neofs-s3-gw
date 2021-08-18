package cache

import (
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"

	"github.com/bluele/gcache"
)

type (
	// SystemCache provides interface for lru cache for objects.
	SystemCache interface {
		Get(key string) *object.Object
		Put(key string, obj *object.Object) error
		Delete(key string) bool
	}

	// systemCache contains cache with objects and lifetime of cache entries.
	systemCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// NewSystemCache creates an object of SystemCache.
func NewSystemCache(cacheSize int, lifetime time.Duration) SystemCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &systemCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *systemCache) Get(key string) *object.Object {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*object.Object)
	if !ok {
		return nil
	}

	return result
}

// Put puts an object to cache.
func (o *systemCache) Put(key string, obj *object.Object) error {
	return o.cache.SetWithExpire(key, obj, o.lifetime)
}

// Delete deletes an object from cache.
func (o *systemCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
