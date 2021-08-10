package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

// ObjectsCache provides interface for lru cache for objects.
type ObjectsCache interface {
	Get(address *object.Address) *object.Object
	Put(address *object.Address, obj object.Object) error
	Delete(address *object.Address) bool
}

const (
	// DefaultObjectsCacheLifetime is a default lifetime of objects in cache.
	DefaultObjectsCacheLifetime = time.Minute * 5
	// DefaultObjectsCacheSize is a default maximum number of objects in cache.
	DefaultObjectsCacheSize = 1e6
)

type (
	// ObjectHeadersCache contains cache with objects and lifetime of cache entries.
	ObjectHeadersCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// New creates an object of ObjectHeadersCache.
func New(cacheSize int, lifetime time.Duration) *ObjectHeadersCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &ObjectHeadersCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *ObjectHeadersCache) Get(address *object.Address) *object.Object {
	entry, err := o.cache.Get(address.String())
	if err != nil {
		return nil
	}

	result, ok := entry.(object.Object)
	if !ok {
		return nil
	}

	return &result
}

// Put puts an object to cache.
func (o *ObjectHeadersCache) Put(address *object.Address, obj object.Object) error {
	return o.cache.SetWithExpire(address.String(), obj, o.lifetime)
}

// Delete deletes an object from cache.
func (o *ObjectHeadersCache) Delete(address *object.Address) bool {
	return o.cache.Remove(address.String())
}
