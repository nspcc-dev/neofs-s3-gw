package cache

import (
	"fmt"
	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"time"
)

type (
	UploadsPartsCache struct {
		cache gcache.Cache
	}
)

const (
	// DefaultUploadsPartsCacheSize is a default maximum number of entries in cache.
	DefaultUploadsPartsCacheSize = 1e4
	// DefaultUploadsPartsCacheLifetime is a default lifetime of entries in  cache.
	DefaultUploadsPartsCacheLifetime = 5 * time.Minute
)

// GetObject returns cached object.
func (u *UploadsPartsCache) Get(key string) []*data.ObjectInfo {
	entry, err := u.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.([]*data.ObjectInfo)
	if !ok {
		return nil
	}

	return result
}

// Put puts a list of objects to cache.
func (u *UploadsPartsCache) Put(key ObjectsListKey, uploads []*data.ObjectInfo) error {
	if len(uploads) == 0 {
		return fmt.Errorf("list is empty, cid: %s, prefix: %s", key.cid, key.prefix)
	}

	return u.cache.Set(key, uploads)
}
