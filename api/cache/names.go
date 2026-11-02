package cache

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"go.uber.org/zap"
)

// ObjectsNameCache provides lru cache for objects.
// This cache contains the result of the current version lookup by object name.
// Key is containerID+objectName.
type ObjectsNameCache struct {
	cache  namesStore
	logger *zap.Logger
}

type namesStore interface {
	Get(key any) (any, error)
	Set(key, value any) error
	Remove(key any) bool
}

type noOpNamesStore struct{}

func (noOpNamesStore) Get(any) (any, error) { return nil, gcache.KeyNotFoundError }
func (noOpNamesStore) Set(any, any) error   { return nil }
func (noOpNamesStore) Remove(any) bool      { return false }

const (
	// DefaultObjectsNameCacheSize is a default maximum number of entries in cache.
	DefaultObjectsNameCacheSize = 1e4
	// DefaultObjectsNameCacheLifetime is a default lifetime of entries in cache.
	// Zero disables the cache.
	DefaultObjectsNameCacheLifetime time.Duration = 0
)

// DefaultObjectsNameConfig returns new default cache expiration values.
func DefaultObjectsNameConfig(logger *zap.Logger) *Config {
	return &Config{
		Size:     DefaultObjectsNameCacheSize,
		Lifetime: DefaultObjectsNameCacheLifetime,
		Logger:   logger,
	}
}

// NewObjectsNameCache creates an object of ObjectsNameCache. Zero lifetime
// disables the cache.
func NewObjectsNameCache(config *Config) *ObjectsNameCache {
	var c = &ObjectsNameCache{cache: noOpNamesStore{}, logger: config.Logger}
	if config.Lifetime > 0 {
		c.cache = gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	}

	return c
}

func (o *ObjectsNameCache) Enabled() bool {
	_, noOp := o.cache.(noOpNamesStore)
	return !noOp
}

// Get returns a cached object. Returns nil if value is missing or the cache is
// disabled.
func (o *ObjectsNameCache) Get(key string) *data.ComprehensiveObjectInfo {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.ComprehensiveObjectInfo)
	if !ok {
		o.logger.Warn("invalid cache entry type", zap.String("actual", fmt.Sprintf("%T", entry)),
			zap.String("expected", fmt.Sprintf("%T", result)))
		return nil
	}

	return result
}

// Put puts an object to cache. It does nothing if the cache is disabled.
func (o *ObjectsNameCache) Put(key string, info *data.ComprehensiveObjectInfo) error {
	return o.cache.Set(key, info)
}

// Delete deletes an object from cache. It does nothing if the cache is disabled.
func (o *ObjectsNameCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
