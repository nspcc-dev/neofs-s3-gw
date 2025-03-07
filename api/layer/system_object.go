package layer

import (
	"bytes"
	"cmp"
	"context"
	"encoding/xml"
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

const (
	AttributeComplianceMode     = ".s3-compliance-mode"
	AttributeRetentionUntilMode = ".s3-retention-until"
	AttributeObjectVersion      = ".s3-object-version"
)

type PutLockInfoParams struct {
	ObjVersion   *ObjectVersion
	NewLock      *data.ObjectLock
	CopiesNumber uint32
	NodeVersion  *data.NodeVersion // optional
}

type locksSearchResult struct {
	ID                 oid.ID
	FilePath           string
	CreationEpoch      uint64
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
			object.FilterCreationEpoch,
			object.AttributeTimestamp,
			object.AttributeExpirationEpoch,
			AttributeComplianceMode,
			AttributeRetentionUntilMode,
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
		filters.AddFilter(AttributeObjectVersion, version, object.MatchStringEqual)
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
			psr.CreationEpoch, err = strconv.ParseUint(item.Attributes[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid creation epoch %s: %w", item.Attributes[1], err)
			}
		}

		if item.Attributes[2] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[2], err)
			}
		}

		if item.Attributes[3] != "" {
			psr.ExpirationEpoch, err = strconv.ParseUint(item.Attributes[3], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid expiration epoch %s: %w", item.Attributes[3], err)
			}
		}

		psr.IsComplianceMode = item.Attributes[4] == "true"

		if item.Attributes[5] != "" {
			psr.RetentionUntilMode, err = time.Parse(time.RFC3339, item.Attributes[5])
			if err != nil {
				return nil, fmt.Errorf("parse retention until attribute: %w", err)
			}
		}

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b locksSearchResult) int {
		if c := cmp.Compare(a.CreationEpoch, b.CreationEpoch); c != 0 { // direct order.
			return c
		}

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
		prm.Attributes[AttributeObjectVersion] = objectVersion
		prm.Attributes[attrS3VersioningState] = data.VersioningEnabled
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

func (n *layer) getCORS(ctx context.Context, bkt *data.BucketInfo) (*data.CORSConfiguration, error) {
	owner := n.Owner(ctx)
	if cors := n.cache.GetCORS(owner, bkt); cors != nil {
		return cors, nil
	}

	objID, err := n.treeService.GetBucketCORS(ctx, bkt)
	objIDNotFound := errors.Is(err, ErrNodeNotFound)
	if err != nil && !objIDNotFound {
		return nil, err
	}

	if objIDNotFound {
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchCORSConfiguration)
	}

	obj, err := n.objectGet(ctx, bkt, objID)
	if err != nil {
		return nil, err
	}

	cors := &data.CORSConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &cors); err != nil {
		return nil, fmt.Errorf("unmarshal cors: %w", err)
	}

	n.cache.PutCORS(owner, bkt, cors)

	return cors, nil
}

func lockObjectKey(objVersion *ObjectVersion) string {
	// todo reconsider forming name since versionID can be "null" or ""
	return ".lock." + objVersion.BktInfo.CID.EncodeToString() + "." + objVersion.ObjectName + "." + objVersion.VersionID
}

func (n *layer) GetBucketSettings(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	owner := n.Owner(ctx)
	if settings := n.cache.GetSettings(owner, bktInfo); settings != nil {
		return settings, nil
	}

	settings, err := n.treeService.GetSettingsNode(ctx, bktInfo)
	if err != nil {
		if !errors.Is(err, ErrNodeNotFound) {
			return nil, err
		}
		settings = &data.BucketSettings{Versioning: data.VersioningUnversioned}
	}

	n.cache.PutSettings(owner, bktInfo, settings)

	return settings, nil
}

func (n *layer) PutBucketSettings(ctx context.Context, p *PutSettingsParams) error {
	if err := n.treeService.PutSettingsNode(ctx, p.BktInfo, p.Settings); err != nil {
		return fmt.Errorf("failed to get settings node: %w", err)
	}

	n.cache.PutSettings(n.Owner(ctx), p.BktInfo, p.Settings)

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

		result[AttributeRetentionUntilMode] = lock.Retention.Until.UTC().Format(time.RFC3339)

		if lock.Retention.IsCompliance {
			result[AttributeComplianceMode] = "true"
		}
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
