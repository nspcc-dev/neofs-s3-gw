package cache

import (
	"time"

	"github.com/bluele/gcache"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// ObjectsNameCache provides lru cache for objects.
// This cache contains mapping nice names to object addresses.
// Key is bucketName+objectName.
type ObjectsNameCache struct {
	cache gcache.Cache
}

const (
	// DefaultObjectsNameCacheSize is a default maximum number of entries in cache.
	DefaultObjectsNameCacheSize = 1e4
	// DefaultObjectsNameCacheLifetime is a default lifetime of entries in cache.
	DefaultObjectsNameCacheLifetime = time.Minute
)

// DefaultObjectsNameConfig returns new default cache expiration values.
func DefaultObjectsNameConfig() *Config {
	return &Config{Size: DefaultObjectsNameCacheSize, Lifetime: DefaultObjectsNameCacheLifetime}
}

// NewObjectsNameCache creates an object of ObjectsNameCache.
func NewObjectsNameCache(config *Config) *ObjectsNameCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	return &ObjectsNameCache{cache: gc}
}

// Get returns a cached object. Returns nil if value is missing.
func (o *ObjectsNameCache) Get(key string) *oid.Address {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(oid.Address)
	if !ok {
		return nil
	}

	return &result
}

// Put puts an object to cache.
func (o *ObjectsNameCache) Put(key string, address oid.Address) error {
	return o.cache.Set(key, address)
}

// Delete deletes an object from cache.
func (o *ObjectsNameCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
