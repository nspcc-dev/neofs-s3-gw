package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

type (
	// SystemCache provides interface for lru cache for objects.
	// This cache contains "system" objects (bucket versioning settings, tagging object etc.).
	// Key is bucketName+systemFileName.
	SystemCache interface {
		Get(key string) *object.Object
		Put(key string, obj *object.Object) error
		Delete(key string) bool
	}

	// SysCache contains cache with objects and lifetime of cache entries.
	SysCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// NewSystemCache creates an object of SystemCache.
func NewSystemCache(cacheSize int, lifetime time.Duration) *SysCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &SysCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *SysCache) Get(key string) *object.Object {
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
func (o *SysCache) Put(key string, obj *object.Object) error {
	return o.cache.SetWithExpire(key, obj, o.lifetime)
}

// Delete deletes an object from cache.
func (o *SysCache) Delete(key string) bool {
	return o.cache.Remove(key)
}

// SystemObjectKey is key to use in SystemCache.
func SystemObjectKey(bucket, obj string) string {
	return bucket + obj
}
