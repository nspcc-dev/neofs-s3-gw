package tree

import (
	"context"
	"sort"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type TreeServiceMock struct {
	settings map[string]*data.BucketSettings
	versions map[string]map[string][]*layer.NodeVersion
	system   map[string]map[string]*layer.BaseNodeVersion
}

func NewTreeService() *TreeServiceMock {
	return &TreeServiceMock{
		settings: make(map[string]*data.BucketSettings),
		versions: make(map[string]map[string][]*layer.NodeVersion),
		system:   make(map[string]map[string]*layer.BaseNodeVersion),
	}
}

func (t *TreeServiceMock) PutSettingsNode(_ context.Context, id *cid.ID, settings *data.BucketSettings) error {
	t.settings[id.String()] = settings
	return nil
}

func (t *TreeServiceMock) GetSettingsNode(_ context.Context, id *cid.ID) (*data.BucketSettings, error) {
	settings, ok := t.settings[id.String()]
	if !ok {
		return nil, layer.ErrNodeNotFound
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

func (t *TreeServiceMock) GetVersions(ctx context.Context, cnrID *cid.ID, objectName string) ([]*layer.NodeVersion, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetLatestVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*layer.NodeVersion, error) {
	cnrVersionsMap, ok := t.versions[cnrID.String()]
	if !ok {
		return nil, layer.ErrNodeNotFound
	}

	versions, ok := cnrVersionsMap[objectName]
	if !ok {
		return nil, layer.ErrNodeNotFound
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ID < versions[j].ID
	})

	if len(versions) != 0 {
		return versions[len(versions)-1], nil
	}

	return nil, layer.ErrNodeNotFound
}

func (t *TreeServiceMock) GetLatestVersionsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetUnversioned(ctx context.Context, cnrID *cid.ID, objectName string) (*layer.NodeVersion, error) {
	panic("implement me")
}

func (t *TreeServiceMock) AddVersion(_ context.Context, cnrID *cid.ID, objectName string, newVersion *layer.NodeVersion) error {
	cnrVersionsMap, ok := t.versions[cnrID.String()]
	if !ok {
		t.versions[cnrID.String()] = map[string][]*layer.NodeVersion{
			objectName: {newVersion},
		}
		return nil
	}

	versions, ok := cnrVersionsMap[objectName]
	if !ok {
		cnrVersionsMap[objectName] = []*layer.NodeVersion{newVersion}
		return nil
	}

	sort.Slice(versions, func(i, j int) bool {
		return versions[i].ID < versions[j].ID
	})

	if len(versions) != 0 {
		newVersion.ID = versions[len(versions)-1].ID + 1
	}

	cnrVersionsMap[objectName] = append(versions, newVersion)

	return nil
}

func (t *TreeServiceMock) RemoveVersion(ctx context.Context, cnrID *cid.ID, nodeID uint64) error {
	panic("implement me")
}

func (t *TreeServiceMock) AddSystemVersion(_ context.Context, cnrID *cid.ID, objectName string, newVersion *layer.BaseNodeVersion) error {
	cnrSystemMap, ok := t.system[cnrID.String()]
	if !ok {
		t.system[cnrID.String()] = map[string]*layer.BaseNodeVersion{
			objectName: newVersion,
		}
		return nil
	}

	cnrSystemMap[objectName] = newVersion

	return nil
}

func (t *TreeServiceMock) GetSystemVersion(_ context.Context, cnrID *cid.ID, objectName string) (*layer.BaseNodeVersion, error) {
	cnrSystemMap, ok := t.system[cnrID.String()]
	if !ok {
		return nil, layer.ErrNodeNotFound
	}

	sysVersion, ok := cnrSystemMap[objectName]
	if !ok {
		return nil, layer.ErrNodeNotFound
	}

	return sysVersion, nil
}

func (t *TreeServiceMock) RemoveSystemVersion(ctx context.Context, cnrID *cid.ID, nodeID uint64) error {
	panic("implement me")
}
