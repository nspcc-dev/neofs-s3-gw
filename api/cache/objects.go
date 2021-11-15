package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-sdk-go/object"
)

// ObjectsCache provides lru cache for objects.
type ObjectsCache struct {
	cache gcache.Cache
}

const (
	// DefaultObjectsCacheLifetime is a default lifetime of entries in objects' cache.
	DefaultObjectsCacheLifetime = time.Minute * 5
	// DefaultObjectsCacheSize is a default maximum number of entries in objects' in cache.
	DefaultObjectsCacheSize = 1e6
)

// DefaultObjectsConfig return new default cache expiration values.
func DefaultObjectsConfig() *Config {
	return &Config{Size: DefaultObjectsCacheSize, Lifetime: DefaultObjectsCacheLifetime}
}

// New creates an object of ObjectHeadersCache.
func New(config *Config) *ObjectsCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	return &ObjectsCache{cache: gc}
}

// Get returns cached object.
func (o *ObjectsCache) Get(address *object.Address) *object.Object {
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
func (o *ObjectsCache) Put(obj object.Object) error {
	return o.cache.Set(obj.ContainerID().String()+"/"+obj.ID().String(), obj)
}

// Delete deletes an object from cache.
func (o *ObjectsCache) Delete(address *object.Address) bool {
	return o.cache.Remove(address.String())
}
