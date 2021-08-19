package cache

import (
	"time"

	"github.com/bluele/gcache"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
)

type (
	// BucketCache provides interface for lru cache for objects.
	BucketCache interface {
		Get(key string) *BucketInfo
		Put(bkt *BucketInfo) error
		Delete(key string) bool
	}

	// BucketInfo stores basic bucket data.
	BucketInfo struct {
		Name     string
		CID      *cid.ID
		Owner    *owner.ID
		Created  time.Time
		BasicACL uint32
	}

	// GetBucketCache contains cache with objects and lifetime of cache entries.
	GetBucketCache struct {
		cache    gcache.Cache
		lifetime time.Duration
	}
)

// NewBucketCache creates an object of BucketCache.
func NewBucketCache(cacheSize int, lifetime time.Duration) *GetBucketCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &GetBucketCache{cache: gc, lifetime: lifetime}
}

// Get returns cached object.
func (o *GetBucketCache) Get(key string) *BucketInfo {
	entry, err := o.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.(*BucketInfo)
	if !ok {
		return nil
	}

	return result
}

// Put puts an object to cache.
func (o *GetBucketCache) Put(bkt *BucketInfo) error {
	return o.cache.SetWithExpire(bkt.Name, bkt, o.lifetime)
}

// Delete deletes an object from cache.
func (o *GetBucketCache) Delete(key string) bool {
	return o.cache.Remove(key)
}

const bktVersionSettingsObject = ".s3-versioning-settings"

// SettingsObjectName is system name for bucket settings file.
func (b *BucketInfo) SettingsObjectName() string {
	return bktVersionSettingsObject
}

// SystemObjectKey is key to use in SystemCache.
func (b *BucketInfo) SystemObjectKey(obj string) string {
	return b.Name + obj
}
