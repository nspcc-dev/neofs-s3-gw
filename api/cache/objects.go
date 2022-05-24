package cache

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

// ObjectsCache provides lru cache for objects.
type ObjectsCache struct {
	cache  gcache.Cache
	logger *zap.Logger
}

const (
	// DefaultObjectsCacheLifetime is a default lifetime of entries in objects' cache.
	DefaultObjectsCacheLifetime = time.Minute * 5
	// DefaultObjectsCacheSize is a default maximum number of entries in objects' cache.
	DefaultObjectsCacheSize = 1e6
)

// DefaultObjectsConfig returns new default cache expiration values.
func DefaultObjectsConfig(logger *zap.Logger) *Config {
	return &Config{
		Size:     DefaultObjectsCacheSize,
		Lifetime: DefaultObjectsCacheLifetime,
		Logger:   logger,
	}
}

// New creates an object of ObjectHeadersCache.
func New(config *Config) *ObjectsCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()
	return &ObjectsCache{cache: gc, logger: config.Logger}
}

// Get returns a cached object.
func (o *ObjectsCache) Get(address oid.Address) *object.Object {
	entry, err := o.cache.Get(address.EncodeToString())
	if err != nil {
		return nil
	}

	result, ok := entry.(object.Object)
	if !ok {
		o.logger.Warn("invalid cache entry type", zap.String("actual", fmt.Sprintf("%T", entry)),
			zap.String("expected", fmt.Sprintf("%T", result)))
		return nil
	}

	return &result
}

// GetObject returns a cached object info.
func (o *ObjectsCache) GetObject(address oid.Address) *data.ObjectInfo {
	entry, err := o.cache.Get(address.EncodeToString())
	if err != nil {
		return nil
	}

	result, ok := entry.(*data.ObjectInfo)
	if !ok {
		return nil
	}

	return result
}

// Put puts an object to cache.
func (o *ObjectsCache) Put(obj object.Object) error {
	cnrID, ok := obj.ContainerID()
	if !ok {
		return fmt.Errorf("empty container id")
	}
	objID, ok := obj.ID()
	if !ok {
		return fmt.Errorf("empty object id")
	}

	var addr oid.Address
	addr.SetContainer(cnrID)
	addr.SetObject(objID)

	return o.cache.Set(addr.EncodeToString(), obj)
}

// PutObject puts an object info to cache.
func (o *ObjectsCache) PutObject(obj *data.ObjectInfo) error {
	cnrID := obj.CID.EncodeToString()
	objID := obj.ID.EncodeToString()
	return o.cache.Set(cnrID+"/"+objID, obj)
}

// Delete deletes an object from cache.
func (o *ObjectsCache) Delete(address oid.Address) bool {
	return o.cache.Remove(address.EncodeToString())
}
