package layer

import (
	"context"
	"encoding/xml"
	errorsStd "errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
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

func (n *layer) PutLockInfo(ctx context.Context, p *PutLockInfoParams) (err error) {
	newLock := p.NewLock

	lockInfo, err := n.getLockDataFromObjects(ctx, p.ObjVersion.BktInfo, p.ObjVersion.ObjectName, p.ObjVersion.VersionID)
	if err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
		return err
	}

	if lockInfo == nil {
		lockInfo = &data.LockInfo{}
	}

	objList, err := n.searchAllVersionsInNeoFS(ctx, p.ObjVersion.BktInfo, p.ObjVersion.BktInfo.Owner, p.ObjVersion.ObjectName, p.ObjVersion.VersionID == "")
	if err != nil {
		return err
	}

	objectToLock := objList[0].GetID()

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
	prmSearch := PrmObjectSearch{
		Container: bkt.CID,
		Filters:   make(object.SearchFilters, 0, 3),
	}

	n.prepareAuthParameters(ctx, &prmSearch.PrmAuth, bkt.Owner)
	prmSearch.Filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	prmSearch.Filters.AddTypeFilter(object.MatchStringEqual, object.TypeLock)
	if version != "" {
		prmSearch.Filters.AddFilter(AttributeObjectVersion, version, object.MatchStringEqual)
	}

	ids, err := n.neoFS.SearchObjects(ctx, prmSearch)
	if err != nil {
		if errorsStd.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("search object version: %w", err)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	var (
		heads = make([]*object.Object, 0, len(ids))
		lock  data.LockInfo
	)

	for i := range ids {
		head, err := n.objectHead(ctx, bkt, ids[i])
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("oid", &ids[i]),
				zap.Stringer("cid", bkt.CID),
				zap.Error(err))

			return nil, fmt.Errorf("couldn't head object: %w", err)
		}

		heads = append(heads, head)
	}

	slices.SortFunc(heads, sortObjectsFunc)
	slices.Reverse(heads)

	for _, head := range heads {
		var (
			expEpoch       uint64
			isCompliance   bool
			retentionUntil time.Time
		)

		for _, attr := range head.Attributes() {
			switch attr.Key() {
			case object.AttributeExpirationEpoch:
				expEpoch, err = strconv.ParseUint(attr.Value(), 10, 64)
				if err != nil {
					return nil, fmt.Errorf("parse expiration epoch: %w", err)
				}
			case AttributeComplianceMode:
				isCompliance = attr.Value() == "true"
			case AttributeRetentionUntilMode:
				retentionUntil, err = time.Parse(time.RFC3339, attr.Value())
				if err != nil {
					return nil, fmt.Errorf("parse retention until attribute: %w", err)
				}
			}
		}

		// legal hold.
		if expEpoch == math.MaxUint64 {
			lock.SetLegalHold(head.GetID())
		} else {
			lock.SetRetention(head.GetID(), retentionUntil.Format(time.RFC3339), isCompliance)
		}
	}

	return &lock, nil
}

func (n *layer) getNodeVersionFromCacheOrNeofs(ctx context.Context, objVersion *ObjectVersion) (nodeVersion *data.NodeVersion, err error) {
	// check cache if node version is stored inside extendedObjectVersion
	nodeVersion = n.getNodeVersionFromCache(n.Owner(ctx), objVersion)
	if nodeVersion == nil {
		// else get node version from tree service
		return n.getNodeVersion(ctx, objVersion)
	}

	return nodeVersion, nil
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
	}

	id, _, err := n.objectPutAndHash(ctx, prm, bktInfo)
	return id, err
}

func (n *layer) GetLockInfo(ctx context.Context, objVersion *ObjectVersion) (*data.LockInfo, error) {
	owner := n.Owner(ctx)
	if lockInfo := n.cache.GetLockInfo(owner, lockObjectKey(objVersion)); lockInfo != nil {
		return lockInfo, nil
	}

	lockInfo, err := n.getLockDataFromObjects(ctx, objVersion.BktInfo, objVersion.ObjectName, objVersion.VersionID)
	if err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
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
	objIDNotFound := errorsStd.Is(err, ErrNodeNotFound)
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
		if !errorsStd.Is(err, ErrNodeNotFound) {
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
