package layer

import (
	"sync"
	"time"

	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
)

/*
	This is an implementation of a cache for ListObjectsV2 which we return to users by ContinuationToken.

	The cache is a map which has a key: (access_key from AccessBox) + container_id and a value: list of objects with
	creation time. After putting a record we start a timer (via time.AfterFunc) that removes the record after
	defaultCacheLifetime value.

	ContinuationToken in our gateway is an objectID in NeoFS.

	We don't keep ContinuationToken in this structure because we assume that users who received the token can reconnect
	to other gateways and they should be able to get a list of objects.
	When we receive the token from the user we just try to find the cache and then we return the list of objects which
	starts from this token (i.e. objectID).
*/

// ObjectsListV2Cache provides interface for cache of ListObjectsV2 in a layer struct.
type (
	ObjectsListV2Cache interface {
		Get(token string, key string) []*ObjectInfo
		Put(key string, objects []*ObjectInfo)
	}
)

var (
	defaultCacheLifetime = time.Second * 60
)

type (
	listObjectsCache struct {
		caches map[string]cache
		mtx    sync.RWMutex
	}
	cache struct {
		list []*ObjectInfo
	}
)

func newListObjectsCache() *listObjectsCache {
	return &listObjectsCache{
		caches: make(map[string]cache),
	}
}

func (l *listObjectsCache) Get(token, key string) []*ObjectInfo {
	l.mtx.RLock()
	defer l.mtx.RUnlock()
	if val, ok := l.caches[key]; ok {
		return trimAfterObjectID(token, val.list)
	}

	return nil
}

func (l *listObjectsCache) Put(key string, objects []*ObjectInfo) {
	var c cache

	l.mtx.Lock()
	defer l.mtx.Unlock()
	c.list = objects
	l.caches[key] = c
	time.AfterFunc(defaultCacheLifetime, func() {
		l.mtx.Lock()
		delete(l.caches, key)
		l.mtx.Unlock()
	})
}

func createKey(accessKey string, cid *cid.ID) string {
	return accessKey + cid.String()
}
