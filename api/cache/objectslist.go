package cache

import (
	"strings"
	"sync"
	"time"

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

// ObjectsListCache provides interface for cache of ListObjectsV2 in a layer struct.
type (
	ObjectsListCache interface {
		Get(key ObjectsListKey) []*object.ID
		Put(key ObjectsListKey, oids []*object.ID)
		Update(key ObjectsListKey, oids []*object.ID)
		Contains(key ObjectsListKey) bool
		CleanCacheEntriesChangedWithPutObject(objectName string, cid *cid.ID)
	}
)

// DefaultObjectsListCacheLifetime is a default lifetime of entries in cache of ListObjects.
const DefaultObjectsListCacheLifetime = time.Second * 60

type (
	// ListObjectsCache contains cache for ListObjects and ListObjectVersions.
	ListObjectsCache struct {
		cacheLifetime time.Duration
		caches        map[ObjectsListKey]objectsListEntry
		mtx           sync.RWMutex
	}
	objectsListEntry struct {
		list []*object.ID
	}
	// ObjectsListKey is a key to find a ObjectsListCache's entry.
	ObjectsListKey struct {
		cid    string
		Prefix string
	}
)

// NewObjectsListCache is a constructor which creates an object of ListObjectsCache with given lifetime of entries.
func NewObjectsListCache(lifetime time.Duration) *ListObjectsCache {
	return &ListObjectsCache{
		caches:        make(map[ObjectsListKey]objectsListEntry),
		cacheLifetime: lifetime,
	}
}

// Get return list of ObjectInfo.
func (l *ListObjectsCache) Get(key ObjectsListKey) []*object.ID {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	if val, ok := l.caches[key]; ok {
		return val.list
	}
	return nil
}

// Put put a list of objects to cache.
func (l *ListObjectsCache) Put(key ObjectsListKey, oids []*object.ID) {
	if len(oids) == 0 {
		return
	}
	if l.Contains(key) {
		return
	}
	c := objectsListEntry{
		list: oids,
	}
	l.mtx.Lock()
	l.caches[key] = c
	l.mtx.Unlock()
	time.AfterFunc(l.cacheLifetime, func() {
		l.mtx.Lock()
		delete(l.caches, key)
		l.mtx.Unlock()
	})
}

// Update updates an entry in cache without restarting timer.
func (l *ListObjectsCache) Update(key ObjectsListKey, oids []*object.ID) {
	if !l.Contains(key) {
		return
	}
	c := objectsListEntry{
		list: oids,
	}
	l.mtx.Lock()
	l.caches[key] = c
	l.mtx.Unlock()
}

// Contains return does cache contain an entry for key or not.
func (l *ListObjectsCache) Contains(key ObjectsListKey) bool {
	l.mtx.RLock()
	_, ok := l.caches[key]
	l.mtx.RUnlock()
	return ok
}

// CleanCacheEntriesChangedWithPutObject deletes entries containing specified object.
func (l *ListObjectsCache) CleanCacheEntriesChangedWithPutObject(objectName string, cid *cid.ID) {
	cidStr := cid.String()
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	for k := range l.caches {
		if cidStr == k.cid && strings.HasPrefix(objectName, k.Prefix) {
			delete(l.caches, k)
		}
	}
}

// CreateObjectsListCacheKey returns ObjectsListKey with given CID, method, prefix, and delimiter.
func CreateObjectsListCacheKey(cid *cid.ID, prefix string) ObjectsListKey {
	p := ObjectsListKey{
		cid:    cid.String(),
		Prefix: prefix,
	}

	return p
}
