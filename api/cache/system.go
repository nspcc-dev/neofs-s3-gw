package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
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
	// DefaultSystemCacheLifetime is a default lifetime of entries in cache.
	DefaultSystemCacheLifetime = 5 * time.Minute
)

// DefaultSystemConfig returns new default cache expiration values.
func DefaultSystemConfig() *Config {
	return &Config{Size: DefaultSystemCacheSize, Lifetime: DefaultSystemCacheLifetime}
}

// NewSystemCache creates an object of SystemCache.
func NewSystemCache(config *Config) *SystemCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	return &SystemCache{cache: gc}
}

// GetObject returns a cached object.
func (o *SystemCache) GetObject(key string) *data.ObjectInfo {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.ObjectInfo)
	if !ok {
		return nil
	}

	return result
}

func (o *SystemCache) GetCORS(key string) *data.CORSConfiguration {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.CORSConfiguration)
	if !ok {
		return nil
	}

	return result
}

func (o *SystemCache) GetSettings(key string) *data.BucketSettings {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.BucketSettings)
	if !ok {
		return nil
	}

	return result
}

func (o *SystemCache) GetNotificationConfiguration(key string) *data.NotificationConfiguration {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.NotificationConfiguration)
	if !ok {
		return nil
	}

	return result
}

// PutObject puts an object to cache.
func (o *SystemCache) PutObject(key string, obj *data.ObjectInfo) error {
	return o.cache.Set(key, obj)
}

func (o *SystemCache) PutCORS(key string, obj *data.CORSConfiguration) error {
	return o.cache.Set(key, obj)
}

func (o *SystemCache) PutSettings(key string, settings *data.BucketSettings) error {
	return o.cache.Set(key, settings)
}

func (o *SystemCache) PutNotificationConfiguration(key string, obj *data.NotificationConfiguration) error {
	return o.cache.Set(key, obj)
}

// Delete deletes an object from cache.
func (o *SystemCache) Delete(key string) bool {
	return o.cache.Remove(key)
}
