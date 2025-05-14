package layer

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type PutLockInfoParams struct {
	ObjVersion   *ObjectVersion
	NewLock      *data.ObjectLock
	CopiesNumber uint32
}

type locksSearchResult struct {
	ID                 oid.ID
	FilePath           string
	CreationTimestamp  int64
	ExpirationEpoch    uint64
	IsComplianceMode   bool
	RetentionUntilMode time.Time
}

func (n *layer) PutLockInfo(ctx context.Context, p *PutLockInfoParams) (err error) {
	newLock := p.NewLock

	lockInfo, err := n.getLockDataFromObjects(ctx, p.ObjVersion.BktInfo, p.ObjVersion.ObjectName, p.ObjVersion.VersionID)
	if err != nil && !errors.Is(err, ErrNodeNotFound) {
		return err
	}

	if lockInfo == nil {
		lockInfo = &data.LockInfo{}
	}

	objList, err := n.searchAllVersionsInNeoFS(ctx, p.ObjVersion.BktInfo, p.ObjVersion.BktInfo.Owner, p.ObjVersion.ObjectName, p.ObjVersion.VersionID == "")
	if err != nil {
		return err
	}

	objectToLock := objList[0].ID

	if newLock.Retention != nil {
		if lockInfo.IsRetentionSet() {
			if lockInfo.IsCompliance() {
				return fmt.Errorf("you cannot change compliance mode")
			}
			if !newLock.Retention.ByPassedGovernance {
				return fmt.Errorf("you cannot bypass governence mode")
			}

			untilDate := lockInfo.UntilDate()
			if len(untilDate) > 0 {
				parsedTime, err := time.Parse(time.RFC3339, untilDate)
				if err != nil {
					return fmt.Errorf("couldn't parse time '%s': %w", untilDate, err)
				}
				if parsedTime.After(newLock.Retention.Until) {
					return fmt.Errorf("you couldn't short the until date")
				}
			}
		}
		lock := &data.ObjectLock{Retention: newLock.Retention}
		retentionOID, err := n.putLockObject(ctx, p.ObjVersion.BktInfo, objectToLock, lock, p.CopiesNumber, p.ObjVersion.ObjectName, p.ObjVersion.VersionID)
		if err != nil {
			return err
		}
		lockInfo.SetRetention(retentionOID, newLock.Retention.Until.UTC().Format(time.RFC3339), newLock.Retention.IsCompliance)
	}

	if newLock.LegalHold != nil {
		if newLock.LegalHold.Enabled && !lockInfo.IsLegalHoldSet() {
			lock := &data.ObjectLock{LegalHold: newLock.LegalHold}
			legalHoldOID, err := n.putLockObject(ctx, p.ObjVersion.BktInfo, objectToLock, lock, p.CopiesNumber, p.ObjVersion.ObjectName, p.ObjVersion.VersionID)
			if err != nil {
				return err
			}
			lockInfo.SetLegalHold(legalHoldOID)
		} else if !newLock.LegalHold.Enabled && lockInfo.IsLegalHoldSet() {
			return s3errors.GetAPIError(s3errors.ErrNotSupported)
		}
	}

	n.cache.PutLockInfo(n.Owner(ctx), lockObjectKey(p.ObjVersion), lockInfo)

	return nil
}

func (n *layer) getLockDataFromObjects(ctx context.Context, bkt *data.BucketInfo, objectName, version string) (*data.LockInfo, error) {
	var (
		filters             = make(object.SearchFilters, 0, 3)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.AttributeTimestamp,
			object.AttributeExpirationEpoch,
			s3headers.AttributeLockMeta,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, bkt.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	filters.AddFilter(s3headers.MetaType, s3headers.TypeLock, object.MatchStringEqual)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeLock)
	if version != "" {
		filters.AddFilter(s3headers.AttributeObjectVersion, version, object.MatchStringEqual)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bkt.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("search objects: %w", err)
	}

	if len(searchResultItems) == 0 {
		return nil, ErrNodeNotFound
	}

	var searchResults = make([]locksSearchResult, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return nil, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = locksSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		if item.Attributes[2] != "" {
			psr.ExpirationEpoch, err = strconv.ParseUint(item.Attributes[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid expiration epoch %s: %w", item.Attributes[2], err)
			}
		}

		if item.Attributes[3] != "" {
			fields := make(map[string]string)
			if err = json.Unmarshal([]byte(item.Attributes[3]), &fields); err != nil {
				return nil, fmt.Errorf("unmarshal retention fields: %w", err)
			}

			psr.IsComplianceMode = fields[s3headers.FieldComplianceMode] == "true"

			if fields[s3headers.FieldRetentionUntilMode] != "" {
				ts, err := strconv.ParseInt(fields[s3headers.FieldRetentionUntilMode], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid retention until time: %w", err)
				}

				psr.RetentionUntilMode = time.Unix(ts, 0).UTC()
			}
		}

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b locksSearchResult) int {
		if c := cmp.Compare(a.CreationTimestamp, b.CreationTimestamp); c != 0 { // direct order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(a.ID[:], b.ID[:]) // direct order.
	}

	slices.SortFunc(searchResults, sortFunc)

	var lock data.LockInfo

	for _, item := range searchResults {
		// legal hold.
		if item.ExpirationEpoch == math.MaxUint64 {
			lock.SetLegalHold(item.ID)
		} else {
			lock.SetRetention(item.ID, item.RetentionUntilMode.Format(time.RFC3339), item.IsComplianceMode)
		}
	}

	return &lock, nil
}

func (n *layer) putLockObject(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID, lock *data.ObjectLock, copiesNumber uint32, objectName, objectVersion string) (oid.ID, error) {
	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Locks:        []oid.ID{objID},
		CreationTime: TimeNow(ctx),
		CopiesNumber: copiesNumber,
		Filepath:     objectName,
	}

	var err error
	prm.Attributes, err = n.attributesFromLock(ctx, lock)
	if err != nil {
		return oid.ID{}, err
	}

	if objectVersion != "" {
		prm.Attributes[s3headers.AttributeObjectVersion] = objectVersion
		prm.Attributes[s3headers.AttributeVersioningState] = data.VersioningEnabled
	}

	prm.Attributes[s3headers.MetaType] = s3headers.TypeLock

	id, _, err := n.objectPutAndHash(ctx, prm, bktInfo)
	return id, err
}

func (n *layer) GetLockInfo(ctx context.Context, objVersion *ObjectVersion) (*data.LockInfo, error) {
	owner := n.Owner(ctx)
	if lockInfo := n.cache.GetLockInfo(owner, lockObjectKey(objVersion)); lockInfo != nil {
		return lockInfo, nil
	}

	lockInfo, err := n.getLockDataFromObjects(ctx, objVersion.BktInfo, objVersion.ObjectName, objVersion.VersionID)
	if err != nil && !errors.Is(err, ErrNodeNotFound) {
		return nil, err
	}
	if lockInfo == nil {
		lockInfo = &data.LockInfo{}
	}

	if !lockInfo.LegalHold().IsZero() || !lockInfo.Retention().IsZero() {
		n.cache.PutLockInfo(owner, lockObjectKey(objVersion), lockInfo)
	}

	return lockInfo, nil
}

func lockObjectKey(objVersion *ObjectVersion) string {
	// todo reconsider forming name since versionID can be "null" or ""
	return ".lock." + objVersion.BktInfo.CID.EncodeToString() + "." + objVersion.ObjectName + "." + objVersion.VersionID
}

func (n *layer) GetBucketSettings(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	if settings := n.cache.GetSettings(bktInfo); settings != nil {
		return settings, nil
	}

	var (
		err      error
		settings = &data.BucketSettings{Versioning: data.VersioningUnversioned}
	)

	id, err := n.searchBucketMetaObjects(ctx, bktInfo, s3headers.TypeBucketSettings)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	if id.IsZero() {
		n.cache.PutSettings(bktInfo, settings)

		return settings, nil
	}

	settingsObj, err := n.objectGet(ctx, bktInfo, id)
	if err != nil {
		return nil, fmt.Errorf("get bucket settings object: %w", err)
	}

	// Took the latest version of the settings file. If you need any migrations,
	// they should be done inside decodeBucketSettings.
	settings, err = decodeBucketSettings(settingsObj)
	if err != nil {
		return nil, fmt.Errorf("decode bucket settings object: %w", err)
	}

	n.cache.PutSettings(bktInfo, settings)

	return settings, nil
}

// decodeBucketSettings decodes and migrates (if required) buket settings file.
func decodeBucketSettings(settingsObj *object.Object) (*data.BucketSettings, error) {
	if settingsObj == nil {
		return nil, fmt.Errorf("bucket settings object is nil")
	}

	var (
		settingsVersion string
		settings        = data.BucketSettings{Versioning: data.VersioningUnversioned}
		versioning      string
	)

	for _, attr := range settingsObj.Attributes() {
		switch attr.Key() {
		case s3headers.BucketSettingsMetaVersion:
			settingsVersion = attr.Value()
		case s3headers.BucketSettingsVersioning:
			versioning = attr.Value()
		default:
			continue
		}
	}

	switch settingsVersion {
	case data.BucketSettingsV1:
		if err := json.Unmarshal(settingsObj.Payload(), &settings); err != nil {
			return nil, fmt.Errorf("decode bucket settings: %w", err)
		}
	default:
		var olc data.ObjectLockConfiguration
		if err := olc.Decode(string(settingsObj.Payload())); err != nil {
			return nil, fmt.Errorf("decode bucket settings: %w", err)
		}

		settings.LockConfiguration = &olc
		settings.Versioning = versioning
	}

	return &settings, nil
}

// PutBucketSettings stores bucket settings. We should save the latest file version only.
func (n *layer) PutBucketSettings(ctx context.Context, p *PutSettingsParams) error {
	payload, err := json.Marshal(p.Settings)
	if err != nil {
		return fmt.Errorf("marshal bucket settings: %w", err)
	}

	prm := PrmObjectCreate{
		Container:    p.BktInfo.CID,
		Creator:      p.BktInfo.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: p.CopiesNumber,
		Attributes: map[string]string{
			s3headers.MetaType:                  s3headers.TypeBucketSettings,
			s3headers.BucketSettingsMetaVersion: data.BucketSettingsV1,
		},
		Payload:     bytes.NewReader(payload),
		PayloadSize: uint64(len(payload)),
	}

	if _, _, err = n.objectPutAndHash(ctx, prm, p.BktInfo); err != nil {
		return fmt.Errorf("create bucket settings object: %w", err)
	}

	n.cache.PutSettings(p.BktInfo, p.Settings)

	return nil
}

func (n *layer) attributesFromLock(ctx context.Context, lock *data.ObjectLock) (map[string]string, error) {
	var (
		err      error
		expEpoch uint64
		result   = make(map[string]string)
	)

	if lock.Retention != nil {
		if _, expEpoch, err = n.neoFS.TimeToEpoch(ctx, TimeNow(ctx), lock.Retention.Until); err != nil {
			return nil, fmt.Errorf("fetch time to epoch: %w", err)
		}

		var (
			retention        = make(map[string]string, 2)
			attributePayload []byte
		)

		retention[s3headers.FieldRetentionUntilMode] = strconv.FormatInt(lock.Retention.Until.UTC().Unix(), 10)

		if lock.Retention.IsCompliance {
			retention[s3headers.FieldComplianceMode] = "true"
		}

		attributePayload, err = json.Marshal(retention)
		if err != nil {
			return nil, fmt.Errorf("marshal attribute: %w", err)
		}

		result[s3headers.AttributeLockMeta] = string(attributePayload)
	}

	if lock.LegalHold != nil && lock.LegalHold.Enabled {
		// todo: (@KirillovDenis) reconsider this when NeoFS will support Legal Hold https://github.com/nspcc-dev/neofs-contract/issues/247
		// Currently lock object must have an expiration epoch.
		// Besides we need to override retention expiration epoch since legal hold cannot be deleted yet.
		expEpoch = math.MaxUint64
	}

	if expEpoch != 0 {
		result[object.AttributeExpirationEpoch] = strconv.FormatUint(expEpoch, 10)
	}

	return result, nil
}
