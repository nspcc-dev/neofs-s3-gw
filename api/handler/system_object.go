package handler

import (
	"context"
	"encoding/xml"
	errorsStd "errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

const (
	AttributeComplianceMode  = ".s3-compliance-mode"
	AttributeExpirationEpoch = "__NEOFS__EXPIRATION_EPOCH"
)

func (h *handler) putLockInfo(ctx context.Context, p *PutLockInfoParams) (err error) {
	newLock := p.NewLock
	versionNode := p.NodeVersion
	// sometimes node version can be provided from executing context
	// if not, then receive node version from tree service
	if versionNode == nil {
		versionNode, err = h.getNodeVersionFromCacheOrNeofs(ctx, p.ObjVersion)
		if err != nil {
			return err
		}
	}

	lockInfo, err := h.treeService.GetLock(ctx, p.ObjVersion.BktInfo, versionNode.ID)
	if err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
		return err
	}

	if lockInfo == nil {
		lockInfo = &data.LockInfo{}
	}

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
		retentionOID, err := h.putLockObject(ctx, p.ObjVersion.BktInfo, versionNode.OID, lock, p.CopiesNumber)
		if err != nil {
			return err
		}
		lockInfo.SetRetention(retentionOID, newLock.Retention.Until.UTC().Format(time.RFC3339), newLock.Retention.IsCompliance)
	}

	if newLock.LegalHold != nil {
		if newLock.LegalHold.Enabled && !lockInfo.IsLegalHoldSet() {
			lock := &data.ObjectLock{LegalHold: newLock.LegalHold}
			legalHoldOID, err := h.putLockObject(ctx, p.ObjVersion.BktInfo, versionNode.OID, lock, p.CopiesNumber)
			if err != nil {
				return err
			}
			lockInfo.SetLegalHold(legalHoldOID)
		} else if !newLock.LegalHold.Enabled && lockInfo.IsLegalHoldSet() {
			if err = h.objectDelete(ctx, p.ObjVersion.BktInfo, lockInfo.LegalHold()); err != nil {
				return fmt.Errorf("couldn't delete lock object '%s' to remove legal hold: %w", lockInfo.LegalHold().EncodeToString(), err)
			}
			lockInfo.ResetLegalHold()
		}
	}

	if err = h.treeService.PutLock(ctx, p.ObjVersion.BktInfo, versionNode.ID, lockInfo); err != nil {
		return fmt.Errorf("couldn't put lock into tree: %w", err)
	}

	h.cache.PutLockInfo(h.Owner(ctx), lockObjectKey(p.ObjVersion), lockInfo)

	return nil
}

func (h *handler) getNodeVersionFromCacheOrNeofs(ctx context.Context, objVersion *ObjectVersion) (nodeVersion *data.NodeVersion, err error) {
	// check cache if node version is stored inside extendedObjectVersion
	nodeVersion = h.getNodeVersionFromCache(h.Owner(ctx), objVersion)
	if nodeVersion == nil {
		// else get node version from tree service
		return h.getNodeVersion(ctx, objVersion)
	}

	return nodeVersion, nil
}

func (h *handler) putLockObject(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID, lock *data.ObjectLock, copiesNumber uint32) (oid.ID, error) {
	prm := PrmObjectCreate{
		Container:    bktInfo.CID,
		Creator:      bktInfo.Owner,
		Locks:        []oid.ID{objID},
		CreationTime: TimeNow(ctx),
		CopiesNumber: copiesNumber,
	}

	var err error
	prm.Attributes, err = h.attributesFromLock(ctx, lock)
	if err != nil {
		return oid.ID{}, err
	}

	id, _, err := h.objectPutAndHash(ctx, prm, bktInfo)
	return id, err
}

func (h *handler) getLockInfo(ctx context.Context, objVersion *ObjectVersion) (*data.LockInfo, error) {
	owner := h.Owner(ctx)
	if lockInfo := h.cache.GetLockInfo(owner, lockObjectKey(objVersion)); lockInfo != nil {
		return lockInfo, nil
	}

	versionNode, err := h.getNodeVersion(ctx, objVersion)
	if err != nil {
		return nil, err
	}

	lockInfo, err := h.treeService.GetLock(ctx, objVersion.BktInfo, versionNode.ID)
	if err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
		return nil, err
	}
	if lockInfo == nil {
		lockInfo = &data.LockInfo{}
	}

	h.cache.PutLockInfo(owner, lockObjectKey(objVersion), lockInfo)

	return lockInfo, nil
}

func (h *handler) getCORS(ctx context.Context, bkt *data.BucketInfo) (*data.CORSConfiguration, error) {
	owner := h.Owner(ctx)
	if cors := h.cache.GetCORS(owner, bkt); cors != nil {
		return cors, nil
	}

	objID, err := h.treeService.GetBucketCORS(ctx, bkt)
	objIDNotFound := errorsStd.Is(err, ErrNodeNotFound)
	if err != nil && !objIDNotFound {
		return nil, err
	}

	if objIDNotFound {
		return nil, errors.GetAPIError(errors.ErrNoSuchCORSConfiguration)
	}

	obj, err := h.objectGet(ctx, bkt, objID)
	if err != nil {
		return nil, err
	}

	cors := &data.CORSConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &cors); err != nil {
		return nil, fmt.Errorf("unmarshal cors: %w", err)
	}

	h.cache.PutCORS(owner, bkt, cors)

	return cors, nil
}

func lockObjectKey(objVersion *ObjectVersion) string {
	// todo reconsider forming name since versionID can be "null" or ""
	return ".lock." + objVersion.BktInfo.CID.EncodeToString() + "." + objVersion.ObjectName + "." + objVersion.VersionID
}

func (h *handler) putBucketSettings(ctx context.Context, p *PutSettingsParams) error {
	if err := h.treeService.PutSettingsNode(ctx, p.BktInfo, p.Settings); err != nil {
		return fmt.Errorf("failed to get settings node: %w", err)
	}

	h.cache.PutSettings(h.Owner(ctx), p.BktInfo, p.Settings)

	return nil
}

func (h *handler) attributesFromLock(ctx context.Context, lock *data.ObjectLock) ([][2]string, error) {
	var (
		err      error
		expEpoch uint64
		result   [][2]string
	)

	if lock.Retention != nil {
		if _, expEpoch, err = h.neoFS.TimeToEpoch(ctx, TimeNow(ctx), lock.Retention.Until); err != nil {
			return nil, fmt.Errorf("fetch time to epoch: %w", err)
		}

		if lock.Retention.IsCompliance {
			result = append(result, [2]string{AttributeComplianceMode, "true"})
		}
	}

	if lock.LegalHold != nil && lock.LegalHold.Enabled {
		// todo: (@KirillovDenis) reconsider this when NeoFS will support Legal Hold https://github.com/nspcc-dev/neofs-contract/issues/247
		// Currently lock object must have an expiration epoch.
		// Besides we need to override retention expiration epoch since legal hold cannot be deleted yet.
		expEpoch = math.MaxUint64
	}

	if expEpoch != 0 {
		result = append(result, [2]string{
			AttributeExpirationEpoch, strconv.FormatUint(expEpoch, 10),
		})
	}

	return result, nil
}
