package cache

import (
	"sync"
	"time"

	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-s3-gw/api"
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
		Get(key ObjectsListKey) []*api.ObjectInfo
		Put(key ObjectsListKey, objects []*api.ObjectInfo)
	}
)

// DefaultObjectsListCacheLifetime is a default lifetime of entries in cache of ListObjects.
const DefaultObjectsListCacheLifetime = time.Second * 60

const (
	// ListObjectsMethod is used to mark a cache entry for ListObjectsV1/V2.
	ListObjectsMethod = "listObjects"
	// ListVersionsMethod is used to mark a cache entry for ListObjectVersions.
	ListVersionsMethod = "listVersions"
)

type (
	// ListObjectsCache contains cache for ListObjects and ListObjectVersions.
	ListObjectsCache struct {
		cacheLifetime time.Duration
		caches        map[ObjectsListKey]objectsListEntry
		mtx           sync.RWMutex
	}
	objectsListEntry struct {
		list []*api.ObjectInfo
	}
	// ObjectsListKey is a key to find a ObjectsListCache's entry.
	ObjectsListKey struct {
		Method    string
		Key       string
		Delimiter string
		Prefix    string
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
func (l *ListObjectsCache) Get(key ObjectsListKey) []*api.ObjectInfo {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	if val, ok := l.caches[key]; ok {
		return val.list
	}
	return nil
}

// Put put a list of objects to cache.
func (l *ListObjectsCache) Put(key ObjectsListKey, objects []*api.ObjectInfo) {
	if len(objects) == 0 {
		return
	}
	var c objectsListEntry
	l.mtx.Lock()
	defer l.mtx.Unlock()
	c.list = objects
	l.caches[key] = c
	time.AfterFunc(l.cacheLifetime, func() {
		l.mtx.Lock()
		delete(l.caches, key)
		l.mtx.Unlock()
	})
}

// CreateObjectsListCacheKey returns ObjectsListKey with given CID, method, prefix, and delimiter.
func CreateObjectsListCacheKey(cid *cid.ID, method, prefix, delimiter string) (ObjectsListKey, error) {
	p := ObjectsListKey{
		Method:    method,
		Key:       cid.String(),
		Delimiter: delimiter,
		Prefix:    prefix,
	}

	return p, nil
}
