package layer

import (
	"context"
	"fmt"
	"slices"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type TreeServiceMock struct {
	settings   map[string]*data.BucketSettings
	versions   map[string]map[string][]*data.NodeVersion
	system     map[string]map[string]*data.BaseNodeVersion
	locks      map[string]map[uint64]*data.LockInfo
	tags       map[string]map[uint64]map[string]string
	multiparts map[string]map[string][]*data.MultipartInfo
	parts      map[string]map[int]*data.PartInfo
}

func (t *TreeServiceMock) GetBucketTagging(_ context.Context, _ *data.BucketInfo) (map[string]string, error) {
	// TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) PutBucketTagging(_ context.Context, _ *data.BucketInfo, _ map[string]string) error {
	// TODO implement me
	panic("implement me")
}

func (t *TreeServiceMock) DeleteBucketTagging(_ context.Context, _ *data.BucketInfo) error {
	// TODO implement me
	panic("implement me")
}

func NewTreeService() *TreeServiceMock {
	return &TreeServiceMock{
		settings:   make(map[string]*data.BucketSettings),
		versions:   make(map[string]map[string][]*data.NodeVersion),
		system:     make(map[string]map[string]*data.BaseNodeVersion),
		locks:      make(map[string]map[uint64]*data.LockInfo),
		tags:       make(map[string]map[uint64]map[string]string),
		multiparts: make(map[string]map[string][]*data.MultipartInfo),
		parts:      make(map[string]map[int]*data.PartInfo),
	}
}

func (t *TreeServiceMock) PutSettingsNode(_ context.Context, bktInfo *data.BucketInfo, settings *data.BucketSettings) error {
	t.settings[bktInfo.CID.EncodeToString()] = settings
	return nil
}

func (t *TreeServiceMock) GetSettingsNode(_ context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	settings, ok := t.settings[bktInfo.CID.EncodeToString()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	return settings, nil
}

func (t *TreeServiceMock) GetNotificationConfigurationNode(_ context.Context, _ *data.BucketInfo) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) PutNotificationConfigurationNode(_ context.Context, _ *data.BucketInfo, _ oid.ID) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetBucketCORS(_ context.Context, _ *data.BucketInfo) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) PutBucketCORS(_ context.Context, _ *data.BucketInfo, _ oid.ID) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) DeleteBucketCORS(_ context.Context, _ *data.BucketInfo) (oid.ID, error) {
	panic("implement me")
}

func (t *TreeServiceMock) CreateMultipartUpload(_ context.Context, bktInfo *data.BucketInfo, info *data.MultipartInfo) (uint64, error) {
	cnrMultipartsMap, ok := t.multiparts[bktInfo.CID.EncodeToString()]
	if !ok {
		t.multiparts[bktInfo.CID.EncodeToString()] = map[string][]*data.MultipartInfo{
			info.Key: {info},
		}
		return 0, nil
	}

	multiparts := cnrMultipartsMap[info.Key]
	if len(multiparts) != 0 {
		info.ID = multiparts[len(multiparts)-1].ID + 1
	}
	cnrMultipartsMap[info.Key] = append(multiparts, info)

	return info.ID, nil
}

func (t *TreeServiceMock) GetMultipartUploadsByPrefix(_ context.Context, _ *data.BucketInfo, _ string) ([]*data.MultipartInfo, error) {
	panic("implement me")
}

func (t *TreeServiceMock) GetMultipartUpload(_ context.Context, bktInfo *data.BucketInfo, objectName, uploadID string) (*data.MultipartInfo, error) {
	cnrMultipartsMap, ok := t.multiparts[bktInfo.CID.EncodeToString()]
	if !ok {
		return nil, ErrNodeNotFound
	}

	multiparts := cnrMultipartsMap[objectName]
	for _, multipart := range multiparts {
		if multipart.UploadID == uploadID {
			return multipart, nil
		}
	}

	return nil, ErrNodeNotFound
}

func (t *TreeServiceMock) AddPart(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64, info *data.PartInfo) (oldObjIDToDelete oid.ID, err error) {
	multipartInfo, err := t.GetMultipartUpload(ctx, bktInfo, info.Key, info.UploadID)
	if err != nil {
		return oid.ID{}, err
	}

	if multipartInfo.ID != multipartNodeID {
		return oid.ID{}, fmt.Errorf("invalid multipart info id")
	}

	partsMap, ok := t.parts[info.UploadID]
	if !ok {
		partsMap = make(map[int]*data.PartInfo)
	}

	partsMap[info.Number] = info

	t.parts[info.UploadID] = partsMap
	return oid.ID{}, nil
}

func (t *TreeServiceMock) GetParts(_ context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64) ([]*data.PartInfo, error) {
	cnrMultipartsMap := t.multiparts[bktInfo.CID.EncodeToString()]

	var foundMultipart *data.MultipartInfo

LOOP:
	for _, multiparts := range cnrMultipartsMap {
		for _, multipart := range multiparts {
			if multipart.ID == multipartNodeID {
				foundMultipart = multipart
				break LOOP
			}
		}
	}

	if foundMultipart == nil {
		return nil, ErrNodeNotFound
	}

	partsMap := t.parts[foundMultipart.UploadID]
	result := make([]*data.PartInfo, 0, len(partsMap))
	for _, part := range partsMap {
		result = append(result, part)
	}

	return result, nil
}

func (t *TreeServiceMock) GetPartByNumber(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64, number int) (*data.PartInfo, error) {
	parts, err := t.GetParts(ctx, bktInfo, multipartNodeID)
	if err != nil {
		return nil, fmt.Errorf("get parts: %w", err)
	}

	if len(parts) == 0 {
		return nil, ErrPartListIsEmpty
	}

	// Sort parts by part number, then by server creation time to make actual last uploaded parts with the same number.
	slices.SortFunc(parts, data.SortPartInfo)

	var pi *data.PartInfo
	for _, part := range parts {
		if part.Number != number {
			continue
		}

		if pi == nil || pi.ServerCreated.Before(part.ServerCreated) {
			pi = part
		}
	}

	return pi, nil
}

func (t *TreeServiceMock) GetPartsAfter(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64, partID int) ([]*data.PartInfo, error) {
	parts, err := t.GetParts(ctx, bktInfo, multipartNodeID)
	if err != nil {
		return nil, err
	}

	mp := make(map[int]*data.PartInfo)
	for _, partInfo := range parts {
		if partInfo.Number <= partID {
			continue
		}

		mapped, ok := mp[partInfo.Number]
		if !ok {
			mp[partInfo.Number] = partInfo
			continue
		}

		if mapped.ServerCreated.After(partInfo.ServerCreated) {
			continue
		}

		mp[partInfo.Number] = partInfo
	}

	if len(mp) == 0 {
		return nil, ErrPartListIsEmpty
	}

	result := make([]*data.PartInfo, 0, len(mp))
	for _, p := range mp {
		result = append(result, p)
	}

	// Sort parts by part number, then by server creation time to make actual last uploaded parts with the same number.
	slices.SortFunc(result, data.SortPartInfo)

	return result, nil
}

func (t *TreeServiceMock) DeleteMultipartUpload(_ context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64) error {
	cnrMultipartsMap := t.multiparts[bktInfo.CID.EncodeToString()]

	var uploadID string

LOOP:
	for key, multiparts := range cnrMultipartsMap {
		for i, multipart := range multiparts {
			if multipart.ID == multipartNodeID {
				uploadID = multipart.UploadID
				cnrMultipartsMap[key] = slices.Delete(multiparts, i, i+1)
				break LOOP
			}
		}
	}

	if uploadID == "" {
		return ErrNodeNotFound
	}

	delete(t.parts, uploadID)
	return nil
}
