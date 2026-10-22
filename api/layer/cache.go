package layer

import (
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

type Cache struct {
	logger         *zap.Logger
	listsCache     *cache.ObjectsListCache
	objCache       *cache.ObjectsCache
	namesCache     *cache.ObjectsNameCache
	bucketCache    *cache.BucketCache
	bucketACLCache *cache.BucketACLCache
	systemCache    *cache.SystemCache
	accessCache    *cache.AccessControlCache
}

// CachesConfig contains params for caches.
type CachesConfig struct {
	Logger        *zap.Logger
	Objects       *cache.Config
	ObjectsList   *cache.Config
	Names         *cache.Config
	Buckets       *cache.Config
	BucketACLs    *cache.Config
	System        *cache.Config
	AccessControl *cache.Config
}

// DefaultCachesConfigs returns filled configs.
func DefaultCachesConfigs(logger *zap.Logger) *CachesConfig {
	return &CachesConfig{
		Logger:        logger,
		Objects:       cache.DefaultObjectsConfig(logger),
		ObjectsList:   cache.DefaultObjectsListConfig(logger),
		Names:         cache.DefaultObjectsNameConfig(logger),
		Buckets:       cache.DefaultBucketConfig(logger),
		BucketACLs:    cache.DefaultBucketACLCacheConfig(logger),
		System:        cache.DefaultSystemConfig(logger),
		AccessControl: cache.DefaultAccessControlConfig(logger),
	}
}

func NewCache(cfg *CachesConfig) *Cache {
	return &Cache{
		logger:         cfg.Logger,
		listsCache:     cache.NewObjectsListCache(cfg.ObjectsList),
		objCache:       cache.New(cfg.Objects),
		namesCache:     cache.NewObjectsNameCache(cfg.Names),
		bucketCache:    cache.NewBucketCache(cfg.Buckets),
		bucketACLCache: cache.NewEACLCache(cfg.BucketACLs),
		systemCache:    cache.NewSystemCache(cfg.System),
		accessCache:    cache.NewAccessControlCache(cfg.AccessControl),
	}
}

func (c *Cache) GetBucket(name, namespace string) *data.BucketInfo {
	return c.bucketCache.Get(name, namespace)
}

func (c *Cache) PutBucket(bktInfo *data.BucketInfo) {
	if err := c.bucketCache.Put(bktInfo); err != nil {
		c.logger.Warn("couldn't put bucket info into cache",
			zap.String("bucket name", bktInfo.Name),
			zap.Stringer("bucket cid", bktInfo.CID),
			zap.Error(err))
	}
}

func (c *Cache) DeleteBucket(name, namespace string) {
	c.bucketCache.Delete(name, namespace)
}

// objectNameCacheKey is the key of the current version lookup in the names and access control
// caches. The prefix keeps it apart from the <cid>/<oid> object keys in the latter, where a name
// may be equal to an object id.
func objectNameCacheKey(cnrID cid.ID, objName string) string {
	return ".name." + cnrID.EncodeToString() + "." + objName
}

// GetObjectByName returns the cached current version lookup for the object name, if owner has
// already made it.
func (c *Cache) GetObjectByName(owner user.ID, cnrID cid.ID, objName string) *data.ComprehensiveObjectInfo {
	key := objectNameCacheKey(cnrID, objName)
	if !c.accessCache.Get(owner, key) {
		return nil
	}

	return c.namesCache.Get(key)
}

func (c *Cache) PutObjectByName(owner user.ID, cnrID cid.ID, objName string, info *data.ComprehensiveObjectInfo) {
	key := objectNameCacheKey(cnrID, objName)

	if err := c.namesCache.Put(key, info); err != nil {
		c.logger.Warn("couldn't put object info to name cache", zap.String("key", key), zap.Error(err))
	}

	if err := c.accessCache.Put(owner, key); err != nil {
		c.logger.Warn("couldn't cache access control operation", zap.Error(err))
	}
}

// DeleteObjectName drops everything cached under the object name: the current version lookup
// and listings containing the object.
func (c *Cache) DeleteObjectName(cnrID cid.ID, objName string) {
	c.namesCache.Delete(objectNameCacheKey(cnrID, objName))
	c.listsCache.CleanCacheEntriesContainingObject(objName, cnrID)
}

func (c *Cache) DeleteObject(addr oid.Address) {
	c.objCache.Delete(addr)
}

func (c *Cache) GetObject(owner user.ID, addr oid.Address) *data.ExtendedObjectInfo {
	if !c.accessCache.Get(owner, addr.String()) {
		return nil
	}

	return c.objCache.GetObject(addr)
}

func (c *Cache) PutObject(owner user.ID, extObjInfo *data.ExtendedObjectInfo) {
	if err := c.objCache.PutObject(extObjInfo); err != nil {
		c.logger.Warn("couldn't add object to cache", zap.Error(err),
			zap.String("object_name", extObjInfo.ObjectInfo.Name), zap.String("bucket_name", extObjInfo.ObjectInfo.Bucket),
			zap.String("cid", extObjInfo.ObjectInfo.CID.EncodeToString()), zap.String("oid", extObjInfo.ObjectInfo.ID.EncodeToString()))
	}

	if err := c.accessCache.Put(owner, extObjInfo.ObjectInfo.Address().EncodeToString()); err != nil {
		c.logger.Warn("couldn't cache access control operation", zap.Error(err))
	}
}

func (c *Cache) GetList(owner user.ID, key cache.ObjectsListKey) []*data.NodeVersion {
	if !c.accessCache.Get(owner, key.String()) {
		return nil
	}

	return c.listsCache.GetVersions(key)
}

func (c *Cache) PutList(owner user.ID, key cache.ObjectsListKey, list []*data.NodeVersion) {
	if err := c.listsCache.PutVersions(key, list); err != nil {
		c.logger.Warn("couldn't cache list of objects", zap.Error(err))
	}

	if err := c.accessCache.Put(owner, key.String()); err != nil {
		c.logger.Warn("couldn't cache access control operation", zap.Error(err))
	}
}

func (c *Cache) GetTagging(owner user.ID, key string) map[string]string {
	if !c.accessCache.Get(owner, key) {
		return nil
	}

	return c.systemCache.GetTagging(key)
}

func (c *Cache) PutTagging(owner user.ID, key string, tags map[string]string) {
	if err := c.systemCache.PutTagging(key, tags); err != nil {
		c.logger.Error("couldn't cache tags", zap.Error(err))
	}

	if err := c.accessCache.Put(owner, key); err != nil {
		c.logger.Warn("couldn't cache access control operation", zap.Error(err))
	}
}

func (c *Cache) DeleteTagging(key string) {
	c.systemCache.Delete(key)
}

func (c *Cache) GetLockInfo(owner user.ID, key string) *data.LockInfo {
	if !c.accessCache.Get(owner, key) {
		return nil
	}

	return c.systemCache.GetLockInfo(key)
}

func (c *Cache) PutLockInfo(owner user.ID, key string, lockInfo *data.LockInfo) {
	if err := c.systemCache.PutLockInfo(key, lockInfo); err != nil {
		c.logger.Error("couldn't cache lock info", zap.Error(err))
	}

	if err := c.accessCache.Put(owner, key); err != nil {
		c.logger.Warn("couldn't cache access control operation", zap.Error(err))
	}
}

func (c *Cache) GetBucketACL(id cid.ID) *eacl.Table {
	return c.bucketACLCache.Get(id)
}

func (c *Cache) PutBucketACL(id cid.ID, acl *eacl.Table) {
	var err = c.bucketACLCache.Put(id, acl)
	if err != nil {
		c.logger.Warn("couldn't cache bucket EACL", zap.Error(err), zap.String("cid", id.String()))
	}
}
