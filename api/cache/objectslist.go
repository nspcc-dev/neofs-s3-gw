package cache

import (
	"fmt"
	"time"

	"github.com/bluele/gcache"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

/*
	This is an implementation of a cache for ListObjectsV2/V1 which we can return to users when we receive a ListObjects
	request.

	The cache is a map which has a key: ObjectsListKey struct and a value: list of objects. After putting a record we
	start a timer (via time.AfterFunc) that removes the record after DefaultObjectsListCacheLifetime value.

	When we get a request from the user we just try to find the suitable and non-expired cache and then we return
	the list of objects. Otherwise we send the request to NeoFS.
*/

type (
	// ObjectsListCache provides interface for cache of ListObjectsV2 in a layer struct.
	ObjectsListCache interface {
		Get(key ObjectsListKey) []*object.ID
		Put(key ObjectsListKey, oids []*object.ID) error
	}
)

const (
	// DefaultObjectsListCacheLifetime is a default lifetime of entries in cache of ListObjects.
	DefaultObjectsListCacheLifetime = time.Second * 60
	// DefaultObjectsListCacheSize is a default size of cache of ListObjects.
	DefaultObjectsListCacheSize = 1e5
)

type (
	// ListObjectsCache contains cache for ListObjects and ListObjectVersions.
	ListObjectsCache struct {
		lifetime time.Duration
		cache    gcache.Cache
	}

	// ObjectsListKey is a key to find a ObjectsListCache's entry.
	ObjectsListKey struct {
		cid    string
		prefix string
	}
)

// NewObjectsListCache is a constructor which creates an object of ListObjectsCache with given lifetime of entries.
func NewObjectsListCache(cacheSize int, lifetime time.Duration) *ListObjectsCache {
	gc := gcache.New(cacheSize).LRU().Build()

	return &ListObjectsCache{
		cache:    gc,
		lifetime: lifetime,
	}
}

// Get return list of ObjectInfo.
func (l *ListObjectsCache) Get(key ObjectsListKey) []*object.ID {
	entry, err := l.cache.Get(key)
	if err != nil {
		return nil
	}

	result, ok := entry.([]*object.ID)
	if !ok {
		return nil
	}

	return result
}

// Put puts a list of objects to cache.
func (l *ListObjectsCache) Put(key ObjectsListKey, oids []*object.ID) error {
	if len(oids) == 0 {
		return fmt.Errorf("list is empty, cid: %s, prefix: %s", key.cid, key.prefix)
	}

	return l.cache.SetWithExpire(key, oids, l.lifetime)
}

// CreateObjectsListCacheKey returns ObjectsListKey with given CID, method, prefix, and delimiter.
func CreateObjectsListCacheKey(cid *cid.ID, prefix string) ObjectsListKey {
	p := ObjectsListKey{
		cid:    cid.String(),
		prefix: prefix,
	}

	return p
}
