package cache

import (
	"time"

	"github.com/bluele/gcache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type (
	// AccessBoxCache stores an access box by its address.
	AccessBoxCache struct {
		cache gcache.Cache
	}

	// Config stores expiration params for cache.
	Config struct {
		Size     int
		Lifetime time.Duration
	}
)

const (
	// DefaultAccessBoxCacheSize is a default maximum number of entries in cache.
	DefaultAccessBoxCacheSize = 100
	// DefaultAccessBoxCacheLifetime is a default lifetime of entries in cache.
	DefaultAccessBoxCacheLifetime = 10 * time.Minute
)

// DefaultAccessBoxConfig returns new default cache expiration values.
func DefaultAccessBoxConfig() *Config {
	return &Config{Size: DefaultAccessBoxCacheSize, Lifetime: DefaultAccessBoxCacheLifetime}
}

// NewAccessBoxCache creates an object of BucketCache.
func NewAccessBoxCache(config *Config) *AccessBoxCache {
	gc := gcache.New(config.Size).LRU().Expiration(config.Lifetime).Build()

	return &AccessBoxCache{cache: gc}
}

// Get returns a cached object.
func (o *AccessBoxCache) Get(address oid.Address) *accessbox.Box {
	entry, err := o.cache.Get(address.EncodeToString())
	if err != nil {
		return nil
	}

	result, ok := entry.(*accessbox.Box)
	if !ok {
		return nil
	}

	return result
}

// Put stores an object to cache.
func (o *AccessBoxCache) Put(address oid.Address, box *accessbox.Box) error {
	return o.cache.Set(address.EncodeToString(), box)
}
