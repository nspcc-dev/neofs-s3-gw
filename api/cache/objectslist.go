package cache

import (
	"fmt"
	"strings"
	"time"

	"github.com/bluele/gcache"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
)

/*
	This is an implementation of a cache which keeps unsorted lists of objects' IDs (all versions)
	for a specified bucket and a prefix.

	The cache contains gcache whose entries have a key: ObjectsListKey struct and a value: list of ids.
	After putting a record it lives for a while (default value is 60 seconds).

	When we receive a request from the user we try to find the suitable and non-expired cache entry, go through the list
	and get ObjectInfos from common object cache or with a request to NeoFS.

	When we put an object into a container we invalidate entries with prefixes that are prefixes of the object's name.
*/

type (
	// ObjectsListCache provides interface for cache of ListObjectsV2 in a layer struct.
	ObjectsListCache interface {
		Get(key ObjectsListKey) []*object.ID
		Put(key ObjectsListKey, oids []*object.ID) error
		CleanCacheEntriesContainingObject(objectName string, cid *cid.ID)
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

// CleanCacheEntriesContainingObject deletes entries containing specified object.
func (l *ListObjectsCache) CleanCacheEntriesContainingObject(objectName string, cid *cid.ID) {
	cidStr := cid.String()
	keys := l.cache.Keys(true)
	for _, key := range keys {
		k, ok := key.(ObjectsListKey)
		if !ok {
			continue
		}
		if cidStr == k.cid && strings.HasPrefix(objectName, k.prefix) {
			l.cache.Remove(k)
		}
	}
}

// CreateObjectsListCacheKey returns ObjectsListKey with given CID and prefix.
func CreateObjectsListCacheKey(cid *cid.ID, prefix string) ObjectsListKey {
	p := ObjectsListKey{
		cid:    cid.String(),
		prefix: prefix,
	}

	return p
}
