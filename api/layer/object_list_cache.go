package layer

import (
	"context"
	"sync"
	"time"

	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
)

/*
	This is an implementation of a cache for ListObjectsV2/V1 which we can return to users when we receive a ListObjects
	request.

	The cache is a map which has a key: cacheOptions struct and a value: list of objects. After putting a record we
	start a timer (via time.AfterFunc) that removes the record after DefaultObjectsListCacheLifetime value.

	When we get a request from the user we just try to find the suitable and non-expired cache and then we return
	the list of objects. Otherwise we send the request to NeoFS.
*/

// ObjectsListCache provides interface for cache of ListObjectsV2 in a layer struct.
type (
	ObjectsListCache interface {
		Get(key cacheOptions) []*ObjectInfo
		Put(key cacheOptions, objects []*ObjectInfo)
	}
)

// DefaultObjectsListCacheLifetime is a default lifetime of entries in cache of ListObjects.
const DefaultObjectsListCacheLifetime = time.Second * 60

const (
	listObjectsMethod  = "listObjects"
	listVersionsMethod = "listVersions"
)

type (
	listObjectsCache struct {
		cacheLifetime time.Duration
		caches        map[cacheOptions]cacheEntry
		mtx           sync.RWMutex
	}
	cacheEntry struct {
		list []*ObjectInfo
	}
	cacheOptions struct {
		method    string
		key       string
		delimiter string
		prefix    string
	}
)

func newListObjectsCache(lifetime time.Duration) *listObjectsCache {
	return &listObjectsCache{
		caches:        make(map[cacheOptions]cacheEntry),
		cacheLifetime: lifetime,
	}
}

func (l *listObjectsCache) Get(key cacheOptions) []*ObjectInfo {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	if val, ok := l.caches[key]; ok {
		return val.list
	}
	return nil
}

func (l *listObjectsCache) Put(key cacheOptions, objects []*ObjectInfo) {
	if len(objects) == 0 {
		return
	}
	var c cacheEntry
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

func createKey(ctx context.Context, cid *cid.ID, method, prefix, delimiter string) (cacheOptions, error) {
	box, err := GetBoxData(ctx)
	if err != nil {
		return cacheOptions{}, err
	}
	p := cacheOptions{
		method:    method,
		key:       box.Gate.AccessKey + cid.String(),
		delimiter: delimiter,
		prefix:    prefix,
	}

	return p, nil
}
