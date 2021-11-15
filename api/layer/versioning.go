package layer

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-sdk-go/object"
)

type objectVersions struct {
	name     string
	objects  []*data.ObjectInfo
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

func (v *objectVersions) isAddListEmpty() bool {
	v.sort()
	return len(v.addList) == 0
}

func (v *objectVersions) appendVersion(oi *data.ObjectInfo) {
	delVers := splitVersions(oi.Headers[versionsDelAttr])
	v.objects = append(v.objects, oi)

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
			o1, o2 := v.objects[i], v.objects[j]
			if o1.CreationEpoch == o2.CreationEpoch {
				l1, l2 := o1.Headers[versionsAddAttr], o2.Headers[versionsAddAttr]
				if len(l1) != len(l2) {
					if strings.HasPrefix(l1, l2) {
						return false
					} else if strings.HasPrefix(l2, l1) {
						return true
					}
				}
				return o1.Version() < o2.Version()
			}
			return o1.CreationEpoch < o2.CreationEpoch
		})

		v.formAddList()
		v.isSorted = true
	}
}

func (v *objectVersions) formAddList() {
	for i := 0; i < len(v.objects); i++ {
		var conflicts [][]string
		for { // forming conflicts set (objects with the same creation epoch)
			addVers := append(splitVersions(v.objects[i].Headers[versionsAddAttr]), v.objects[i].Version())
			conflicts = append(conflicts, addVers)
			if i == len(v.objects)-1 || v.objects[i].CreationEpoch != v.objects[i+1].CreationEpoch ||
				containsVersions(v.objects[i+1], addVers) {
				break
			}
			i++
		}

		if len(conflicts) == 1 {
			v.addList = addIfNotContains(v.addList, conflicts[0])
			continue
		}

		commonVersions, prevConflictedVersions, conflictedVersions := mergeVersionsConflicts(conflicts)
		v.addList = commonVersions
		v.addList = addIfNotContains(v.addList, prevConflictedVersions)
		v.addList = addIfNotContains(v.addList, conflictedVersions)
	}
}

func containsVersions(obj *data.ObjectInfo, versions []string) bool {
	header := obj.Headers[versionsAddAttr]
	for _, version := range versions {
		if !strings.Contains(header, version) {
			return false
		}
	}
	return true
}

func addIfNotContains(list1, list2 []string) []string {
	for _, add := range list2 {
		if !contains(list1, add) {
			list1 = append(list1, add)
		}
	}
	return list1
}

func mergeVersionsConflicts(conflicts [][]string) ([]string, []string, []string) {
	var currentVersions []string
	var prevVersions []string
	minLength := math.MaxInt32
	for _, conflicted := range conflicts {
		if len(conflicted)-1 < minLength {
			minLength = len(conflicted) - 1
		}
		//last := conflicted[len(conflicted)-1]
		//conflicts[j] = conflicted[:len(conflicted)-1]
		//currentVersions = append(currentVersions, last)
	}
	var commonAddedVersions []string
	diffIndex := 0
LOOP:
	for k := 0; k < minLength; k++ {
		candidate := conflicts[0][k]
		for _, conflicted := range conflicts {
			if conflicted[k] != candidate {
				diffIndex = k
				break LOOP
			}
		}
		commonAddedVersions = append(commonAddedVersions, candidate)
	}

	for _, conflicted := range conflicts {
		for j := diffIndex; j < len(conflicted); j++ {
			prevVersions = append(prevVersions, conflicted[j])
		}
	}

	sort.Strings(prevVersions)
	sort.Strings(currentVersions)
	return commonAddedVersions, prevVersions, currentVersions
}

func (v *objectVersions) isEmpty() bool {
	return v == nil || len(v.objects) == 0
}

func (v *objectVersions) getLast() *data.ObjectInfo {
	if v.isEmpty() {
		return nil
	}

	v.sort()
	existedVersions := v.existedVersions()
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

func (v *objectVersions) existedVersions() []string {
	v.sort()
	var res []string
	for _, add := range v.addList {
		if !contains(v.delList, add) {
			res = append(res, add)
		}
	}
	return res
}

func (v *objectVersions) getFiltered(reverse bool) []*data.ObjectInfo {
	if len(v.objects) == 0 {
		return nil
	}

	v.sort()
	existedVersions := v.existedVersions()
	res := make([]*data.ObjectInfo, 0, len(v.objects))

	for _, version := range v.objects {
		delMark := version.Headers[versionsDeleteMarkAttr]
		if contains(existedVersions, version.Version()) && (delMark == delMarkFullObject || delMark == "") {
			res = append(res, version)
		}
	}

	if reverse {
		for i, j := 0, len(res)-1; i < j; i, j = i+1, j-1 {
			res[i], res[j] = res[j], res[i]
		}
	}

	return res
}

func (v *objectVersions) getAddHeader() string {
	v.sort()
	return strings.Join(v.addList, ",")
}

func (v *objectVersions) getDelHeader() string {
	return strings.Join(v.delList, ",")
}

func (v *objectVersions) getVersion(oid *object.ID) *data.ObjectInfo {
	for _, version := range v.objects {
		if version.Version() == oid.String() {
			if contains(v.delList, oid.String()) {
				return nil
			}
			return version
		}
	}
	return nil
}
func (n *layer) PutBucketVersioning(ctx context.Context, p *PutVersioningParams) (*data.ObjectInfo, error) {
	bktInfo, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	metadata := map[string]string{
		attrSettingsVersioningEnabled: strconv.FormatBool(p.Settings.VersioningEnabled),
	}

	s := &PutSystemObjectParams{
		BktInfo:  bktInfo,
		ObjName:  bktInfo.SettingsObjectName(),
		Metadata: metadata,
		Prefix:   "",
		Reader:   nil,
	}

	return n.putSystemObject(ctx, s)
}

func (n *layer) GetBucketVersioning(ctx context.Context, bucketName string) (*BucketSettings, error) {
	bktInfo, err := n.GetBucketInfo(ctx, bucketName)
	if err != nil {
		return nil, err
	}

	return n.getBucketSettings(ctx, bktInfo)
}

func (n *layer) ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error) {
	var (
		versions   map[string]*objectVersions
		allObjects = make([]*data.ObjectInfo, 0, p.MaxKeys)
		res        = &ListObjectVersionsInfo{}
		reverse    = true
	)

	bkt, err := n.GetBucketInfo(ctx, p.Bucket)
	if err != nil {
		return nil, err
	}

	if versions, err = n.getAllObjectsVersions(ctx, bkt, p.Prefix, p.Delimiter); err != nil {
		return nil, err
	}

	sortedNames := make([]string, 0, len(versions))
	for k := range versions {
		sortedNames = append(sortedNames, k)
	}
	sort.Strings(sortedNames)

	for _, name := range sortedNames {
		allObjects = append(allObjects, versions[name].getFiltered(reverse)...)
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
		if i == 0 || allObjects[i-1].Name != obj.Name {
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

func contains(list []string, elem string) bool {
	for _, item := range list {
		if elem == item {
			return true
		}
	}
	return false
}

func (n *layer) getBucketSettings(ctx context.Context, bktInfo *data.BucketInfo) (*BucketSettings, error) {
	objInfo, err := n.headSystemObject(ctx, bktInfo, bktInfo.SettingsObjectName())
	if err != nil {
		return nil, err
	}

	return objectInfoToBucketSettings(objInfo), nil
}

func objectInfoToBucketSettings(info *data.ObjectInfo) *BucketSettings {
	res := &BucketSettings{}

	enabled, ok := info.Headers[attrSettingsVersioningEnabled]
	if ok {
		if parsed, err := strconv.ParseBool(enabled); err == nil {
			res.VersioningEnabled = parsed
		}
	}
	return res
}

func (n *layer) checkVersionsExist(ctx context.Context, bkt *data.BucketInfo, obj *VersionedObject) (*data.ObjectInfo, error) {
	id := object.NewID()
	if err := id.Parse(obj.VersionID); err != nil {
		return nil, errors.GetAPIError(errors.ErrInvalidVersion)
	}

	versions, err := n.headVersions(ctx, bkt, obj.Name)
	if err != nil {
		return nil, err
	}
	version := versions.getVersion(id)
	if version == nil {
		return nil, errors.GetAPIError(errors.ErrInvalidVersion)
	}

	return version, nil
}
