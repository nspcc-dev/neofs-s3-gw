package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

// ObjectsNameCache provides interface for lru cache for objects.
// This cache contains mapping nice name to object addresses.
// Key is bucketName+objectName.
type ObjectsNameCache interface {
	Get(key string) *object.Address
	Put(key string, address *object.Address) error
	Delete(key string) bool
}

type (
	// NameCache contains cache with objects and lifetime of cache entries.
	NameCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// NewObjectsNameCache creates an object of ObjectsNameCache.
func NewObjectsNameCache(cacheSize int, lifetime time.Duration) *NameCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &NameCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *NameCache) Get(key string) *object.Address {
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
func (o *NameCache) Put(key string, address *object.Address) error {
	return o.cache.SetWithExpire(key, address, o.lifetime)
}

// Delete deletes an object from cache.
func (o *NameCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
