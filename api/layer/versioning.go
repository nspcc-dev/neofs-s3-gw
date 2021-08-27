package layer

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
)

type objectVersions struct {
	name     string
	objects  []*api.ObjectInfo
	addList  []string
	delList  []string
	isSorted bool
}

const (
	unversionedObjectVersionID    = "null"
	objectSystemAttributeName     = "S3-System-name"
	attrVersionsIgnore            = "S3-Versions-ignore"
	attrSettingsVersioningEnabled = "S3-Settings-Versioning-enabled"
	versionsDelAttr               = "S3-Versions-del"
	versionsAddAttr               = "S3-Versions-add"
	versionsDeleteMarkAttr        = "S3-Versions-delete-mark"
	delMarkFullObject             = "*"
)

func newObjectVersions(name string) *objectVersions {
	return &objectVersions{name: name}
}

func (v *objectVersions) appendVersion(oi *api.ObjectInfo) {
	addVers := append(splitVersions(oi.Headers[versionsAddAttr]), oi.Version())
	delVers := splitVersions(oi.Headers[versionsDelAttr])
	v.objects = append(v.objects, oi)
	for _, add := range addVers {
		if !contains(v.addList, add) {
			v.addList = append(v.addList, add)
		}
	}
	for _, del := range delVers {
		if !contains(v.delList, del) {
			v.delList = append(v.delList, del)
		}
	}
	v.isSorted = false
}

func (v *objectVersions) sort() {
	if !v.isSorted {
		sort.Slice(v.objects, func(i, j int) bool {
			return less(v.objects[i], v.objects[j])
		})
		v.isSorted = true
	}
}

func (v *objectVersions) getLast() *api.ObjectInfo {
	if len(v.objects) == 0 {
		return nil
	}

	v.sort()
	existedVersions := getExistedVersions(v)
	for i := len(v.objects) - 1; i >= 0; i-- {
		if contains(existedVersions, v.objects[i].Version()) {
			delMarkHeader := v.objects[i].Headers[versionsDeleteMarkAttr]
			if delMarkHeader == "" {
				return v.objects[i]
			}
			if delMarkHeader == delMarkFullObject {
				return nil
			}
		}
	}

	return nil
}

func (v *objectVersions) getFiltered() []*api.ObjectInfo {
	if len(v.objects) == 0 {
		return nil
	}

	v.sort()
	existedVersions := getExistedVersions(v)
	res := make([]*api.ObjectInfo, 0, len(v.objects))

	for _, version := range v.objects {
		delMark := version.Headers[versionsDeleteMarkAttr]
		if contains(existedVersions, version.Version()) && (delMark == delMarkFullObject || delMark == "") {
			res = append(res, version)
		}
	}

	return res
}

func (v *objectVersions) getAddHeader() string {
	return strings.Join(v.addList, ",")
}

func (v *objectVersions) getDelHeader() string {
	return strings.Join(v.delList, ",")
}

func (v *objectVersions) getVersion(oid *object.ID) *api.ObjectInfo {
	for _, version := range v.objects {
		if version.ID == oid {
			return version
		}
	}
	return nil
}
func (n *layer) PutBucketVersioning(ctx context.Context, p *PutVersioningParams) (*api.ObjectInfo, error) {
	bktInfo, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	metadata := map[string]string{
		attrSettingsVersioningEnabled: strconv.FormatBool(p.Settings.VersioningEnabled),
	}

	meta, err := n.putSystemObject(ctx, bktInfo, bktInfo.SettingsObjectName(), metadata, "")
	if err != nil {
		return nil, err
	}

	return objInfoFromMeta(bktInfo, meta), nil
}

func (n *layer) GetBucketVersioning(ctx context.Context, bucketName string) (*BucketSettings, error) {
	bktInfo, err := n.GetBucketInfo(ctx, bucketName)
	if err != nil {
		return nil, err
	}

	return n.getBucketSettings(ctx, bktInfo)
}

func (n *layer) ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error) {
	var versions map[string]*objectVersions
	res := &ListObjectVersionsInfo{}

	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	cacheKey, err := createKey(bkt.CID, listVersionsMethod, p.Prefix, p.Delimiter)
	if err != nil {
		return nil, err
	}

	allObjects := n.listsCache.Get(cacheKey)
	if allObjects == nil {
		versions, err = n.getAllObjectsVersions(ctx, bkt, p.Prefix, p.Delimiter)
		if err != nil {
			return nil, err
		}

		sortedNames := make([]string, 0, len(versions))
		for k := range versions {
			sortedNames = append(sortedNames, k)
		}
		sort.Strings(sortedNames)

		allObjects = make([]*api.ObjectInfo, 0, p.MaxKeys)
		for _, name := range sortedNames {
			allObjects = append(allObjects, versions[name].getFiltered()...)
		}

		// putting to cache a copy of allObjects because allObjects can be modified further
		n.listsCache.Put(cacheKey, append([]*api.ObjectInfo(nil), allObjects...))
	}

	for i, obj := range allObjects {
		if obj.Name >= p.KeyMarker && obj.Version() >= p.VersionIDMarker {
			allObjects = allObjects[i:]
			break
		}
	}

	res.CommonPrefixes, allObjects = triageObjects(allObjects)

	if len(allObjects) > p.MaxKeys {
		res.IsTruncated = true
		res.NextKeyMarker = allObjects[p.MaxKeys].Name
		res.NextVersionIDMarker = allObjects[p.MaxKeys].Version()

		allObjects = allObjects[:p.MaxKeys]
		res.KeyMarker = allObjects[p.MaxKeys-1].Name
		res.VersionIDMarker = allObjects[p.MaxKeys-1].Version()
	}

	objects := make([]*ObjectVersionInfo, len(allObjects))
	for i, obj := range allObjects {
		objects[i] = &ObjectVersionInfo{Object: obj}
		if i == len(allObjects)-1 || allObjects[i+1].Name != obj.Name {
			objects[i].IsLatest = true
		}
	}

	res.Version, res.DeleteMarker = triageVersions(objects)
	return res, nil
}

func triageVersions(objVersions []*ObjectVersionInfo) ([]*ObjectVersionInfo, []*ObjectVersionInfo) {
	if len(objVersions) == 0 {
		return nil, nil
	}

	var resVersion []*ObjectVersionInfo
	var resDelMarkVersions []*ObjectVersionInfo

	for _, version := range objVersions {
		if version.Object.Headers[versionsDeleteMarkAttr] == delMarkFullObject {
			resDelMarkVersions = append(resDelMarkVersions, version)
		} else {
			resVersion = append(resVersion, version)
		}
	}

	return resVersion, resDelMarkVersions
}

func less(ov1, ov2 *api.ObjectInfo) bool {
	if ov1.CreationEpoch == ov2.CreationEpoch {
		return ov1.Version() < ov2.Version()
	}
	return ov1.CreationEpoch < ov2.CreationEpoch
}

func contains(list []string, elem string) bool {
	for _, item := range list {
		if elem == item {
			return true
		}
	}
	return false
}

func (n *layer) getBucketSettings(ctx context.Context, bktInfo *api.BucketInfo) (*BucketSettings, error) {
	objInfo, err := n.getSystemObject(ctx, bktInfo, bktInfo.SettingsObjectName())
	if err != nil {
		return nil, err
	}

	return objectInfoToBucketSettings(objInfo), nil
}

func objectInfoToBucketSettings(info *api.ObjectInfo) *BucketSettings {
	res := &BucketSettings{}

	enabled, ok := info.Headers[attrSettingsVersioningEnabled]
	if ok {
		if parsed, err := strconv.ParseBool(enabled); err == nil {
			res.VersioningEnabled = parsed
		}
	}
	return res
}

func (n *layer) checkVersionsExist(ctx context.Context, bkt *api.BucketInfo, obj *VersionedObject) (*object.ID, error) {
	id := object.NewID()
	if err := id.Parse(obj.VersionID); err != nil {
		return nil, errors.GetAPIError(errors.ErrInvalidVersion)
	}

	versions, err := n.headVersions(ctx, bkt, obj.Name)
	if err != nil {
		return nil, err
	}
	if !contains(getExistedVersions(versions), obj.VersionID) {
		return nil, errors.GetAPIError(errors.ErrInvalidVersion)
	}

	return id, nil
}
