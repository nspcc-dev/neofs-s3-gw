package tree

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type TreeServiceMock struct {
	settings map[string]*data.BucketSettings
	versions map[string]map[string][]*data.NodeVersion
	system   map[string]map[string]*data.BaseNodeVersion
}

func (t *TreeServiceMock) GetObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) (map[string]string, error) {
	//TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) PutObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion, tagSet map[string]string) error {
	//TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) DeleteObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) error {
	//TODO implement me
	panic("implement me")
}

var ErrNodeNotFound = errors.New("not found")

func NewTreeService() *TreeServiceMock {
	return &TreeServiceMock{
		settings: make(map[string]*data.BucketSettings),
		versions: make(map[string]map[string][]*data.NodeVersion),
		system:   make(map[string]map[string]*data.BaseNodeVersion),
	}
}

func (t *TreeServiceMock) PutSettingsNode(_ context.Context, id *cid.ID, settings *data.BucketSettings) error {
	t.settings[id.String()] = settings
	return nil
}

func (t *TreeServiceMock) GetSettingsNode(_ context.Context, id *cid.ID) (*data.BucketSettings, error) {
	settings, ok := t.settings[id.String()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	return settings, nil
}

func (t *TreeServiceMock) GetNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) PutNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) PutBucketCORS(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) DeleteBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetVersions(_ context.Context, cnrID *cid.ID, objectName string) ([]*data.NodeVersion, error) {
	cnrVersionsMap, ok := t.versions[cnrID.String()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	versions, ok := cnrVersionsMap[objectName]
	if !ok {
		return nil, ErrNodeNotFound
	}

	return versions, nil
}

func (t *TreeServiceMock) GetLatestVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*data.NodeVersion, error) {
	cnrVersionsMap, ok := t.versions[cnrID.String()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	versions, ok := cnrVersionsMap[objectName]
	if !ok {
		return nil, ErrNodeNotFound
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ID < versions[j].ID
	})

	if len(versions) != 0 {
		return versions[len(versions)-1], nil
	}

	return nil, ErrNodeNotFound
}

func (t *TreeServiceMock) GetLatestVersionsByPrefix(_ context.Context, cnrID *cid.ID, prefix string) ([]oid.ID, error) {
	cnrVersionsMap, ok := t.versions[cnrID.String()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	var result []oid.ID

	for key, versions := range cnrVersionsMap {
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		sort.Slice(versions, func(i, j int) bool {
			return versions[i].ID < versions[j].ID
		})

		if len(versions) != 0 {
			result = append(result, versions[len(versions)-1].OID)
		}
	}

	return result, nil
}

func (t *TreeServiceMock) GetUnversioned(ctx context.Context, cnrID *cid.ID, objectName string) (*data.NodeVersion, error) {
	panic("implement me")
}

func (t *TreeServiceMock) AddVersion(_ context.Context, cnrID *cid.ID, objectName string, newVersion *data.NodeVersion) error {
	cnrVersionsMap, ok := t.versions[cnrID.String()]
	if !ok {
		t.versions[cnrID.String()] = map[string][]*data.NodeVersion{
			objectName: {newVersion},
		}
		return nil
	}

	versions, ok := cnrVersionsMap[objectName]
	if !ok {
		cnrVersionsMap[objectName] = []*data.NodeVersion{newVersion}
		return nil
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ID < versions[j].ID
	})

	if len(versions) != 0 {
		newVersion.ID = versions[len(versions)-1].ID + 1
	}

	result := versions

	if newVersion.IsUnversioned {
		result = make([]*data.NodeVersion, 0, len(versions))
		for _, node := range versions {
			if !node.IsUnversioned {
				result = append(result, node)
			}

		}
	}

	cnrVersionsMap[objectName] = append(result, newVersion)

	return nil
}

func (t *TreeServiceMock) RemoveVersion(ctx context.Context, cnrID *cid.ID, nodeID uint64) error {
	panic("implement me")
}

func (t *TreeServiceMock) AddSystemVersion(_ context.Context, cnrID *cid.ID, objectName string, newVersion *data.BaseNodeVersion) error {
	cnrSystemMap, ok := t.system[cnrID.String()]
	if !ok {
		t.system[cnrID.String()] = map[string]*data.BaseNodeVersion{
			objectName: newVersion,
		}
		return nil
	}

	cnrSystemMap[objectName] = newVersion

	return nil
}

func (t *TreeServiceMock) GetSystemVersion(_ context.Context, cnrID *cid.ID, objectName string) (*data.BaseNodeVersion, error) {
	cnrSystemMap, ok := t.system[cnrID.String()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	sysVersion, ok := cnrSystemMap[objectName]
	if !ok {
		return nil, ErrNodeNotFound
	}

	return sysVersion, nil
}

func (t *TreeServiceMock) RemoveSystemVersion(ctx context.Context, cnrID *cid.ID, nodeID uint64) error {
	panic("implement me")
}

func (t *TreeServiceMock) GetAllVersionsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]*data.NodeVersion, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetObjectTagging(ctx context.Context, p *data.ObjectTaggingInfo) (map[string]string, error) {
	//TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) PutObjectTagging(ctx context.Context, p *data.ObjectTaggingInfo) error {
	//TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) DeleteObjectTagging(ctx context.Context, p *data.ObjectTaggingInfo) error {
	//TODO implement me
	panic("implement me")
}
