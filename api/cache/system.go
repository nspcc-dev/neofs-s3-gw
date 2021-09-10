package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

// SystemCache provides lru cache for objects.
// This cache contains "system" objects (bucket versioning settings, tagging object etc.).
// Key is bucketName+systemFileName.
type SystemCache struct {
	cache gcache.Cache
}

const (
	// DefaultSystemCacheSize is a default maximum number of entries in cache.
	DefaultSystemCacheSize = 1e4
	// DefaultSystemCacheLifetime is a default lifetime of entries in  cache.
	DefaultSystemCacheLifetime = 5 * time.Minute
)

// DefaultSystemConfig return new default cache expiration values.
func DefaultSystemConfig() *Config {
	return &Config{Size: DefaultSystemCacheSize, Lifetime: DefaultSystemCacheLifetime}
}

// NewSystemCache creates an object of SystemCache.
func NewSystemCache(config *Config) *SystemCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	return &SystemCache{cache: gc}
}

// Get returns cached object.
func (o *SystemCache) Get(key string) *object.Object {
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
func (o *SystemCache) Put(key string, obj *object.Object) error {
	return o.cache.Set(key, obj)
}

// Delete deletes an object from cache.
func (o *SystemCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
