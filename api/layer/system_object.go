package layer

import (
	"context"
	"encoding/xml"
	errorsStd "errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

const (
	AttributeComplianceMode  = ".s3-compliance-mode"
	AttributeExpirationEpoch = "__NEOFS__EXPIRATION_EPOCH"
)

func (n *layer) PutLockInfo(ctx context.Context, objVersion *ObjectVersion, newLock *data.ObjectLock) error {
	cnrID := objVersion.BktInfo.CID
	versionNode, err := n.getNodeVersion(ctx, objVersion)
	if err != nil {
		return err
	}

	lockInfo, err := n.treeService.GetLock(ctx, cnrID, versionNode.ID)
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
		retentionOID, err := n.putLockObject(ctx, objVersion.BktInfo, versionNode.OID, lock)
		if err != nil {
			return err
		}
		lockInfo.SetRetention(retentionOID, newLock.Retention.Until.UTC().Format(time.RFC3339), newLock.Retention.IsCompliance)
	}

	if newLock.LegalHold != nil {
		if newLock.LegalHold.Enabled && !lockInfo.IsLegalHoldSet() {
			lock := &data.ObjectLock{LegalHold: newLock.LegalHold}
			legalHoldOID, err := n.putLockObject(ctx, objVersion.BktInfo, versionNode.OID, lock)
			if err != nil {
				return err
			}
			lockInfo.SetLegalHold(legalHoldOID)
		} else if !newLock.LegalHold.Enabled && lockInfo.IsLegalHoldSet() {
			if err = n.objectDelete(ctx, objVersion.BktInfo, lockInfo.LegalHold()); err != nil {
				return fmt.Errorf("couldn't delete lock object '%s' to remove legal hold: %w", lockInfo.LegalHold().EncodeToString(), err)
			}
			lockInfo.ResetLegalHold()
		}
	}

	if err = n.treeService.PutLock(ctx, cnrID, versionNode.ID, lockInfo); err != nil {
		return fmt.Errorf("couldn't put lock into tree: %w", err)
	}

	if err = n.systemCache.PutLockInfo(lockObjectKey(objVersion), lockInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) putLockObject(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID, lock *data.ObjectLock) (oid.ID, error) {
	prm := PrmObjectCreate{
		Container: bktInfo.CID,
		Creator:   bktInfo.Owner,
		Locks:     []oid.ID{objID},
	}

	var err error
	prm.Attributes, err = n.attributesFromLock(ctx, lock)
	if err != nil {
		return oid.ID{}, err
	}

	id, _, err := n.objectPutAndHash(ctx, prm, bktInfo)
	return id, err
}

func (n *layer) GetLockInfo(ctx context.Context, objVersion *ObjectVersion) (*data.LockInfo, error) {
	if lockInfo := n.systemCache.GetLockInfo(lockObjectKey(objVersion)); lockInfo != nil {
		return lockInfo, nil
	}

	versionNode, err := n.getNodeVersion(ctx, objVersion)
	if err != nil {
		return nil, err
	}

	lockInfo, err := n.treeService.GetLock(ctx, objVersion.BktInfo.CID, versionNode.ID)
	if err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
		return nil, err
	}
	if lockInfo == nil {
		lockInfo = &data.LockInfo{}
	}

	if err = n.systemCache.PutLockInfo(lockObjectKey(objVersion), lockInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return lockInfo, nil
}

func (n *layer) getCORS(ctx context.Context, bkt *data.BucketInfo, sysName string) (*data.CORSConfiguration, error) {
	if cors := n.systemCache.GetCORS(systemObjectKey(bkt, sysName)); cors != nil {
		return cors, nil
	}
	objID, err := n.treeService.GetBucketCORS(ctx, bkt.CID)
	objIDNotFound := errorsStd.Is(err, ErrNodeNotFound)
	if err != nil && !objIDNotFound {
		return nil, err
	}

	if objIDNotFound {
		return nil, errors.GetAPIError(errors.ErrNoSuchCORSConfiguration)
	}

	obj, err := n.objectGet(ctx, bkt, objID)
	if err != nil {
		return nil, err
	}

	cors := &data.CORSConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &cors); err != nil {
		return nil, fmt.Errorf("unmarshal cors: %w", err)
	}

	if err = n.systemCache.PutCORS(systemObjectKey(bkt, sysName), cors); err != nil {
		objID, _ := obj.ID()
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", &objID),
			zap.String("bucket id", bkt.CID.EncodeToString()),
			zap.Error(err))
	}

	return cors, nil
}

// systemObjectKey is a key to use in SystemCache.
func systemObjectKey(bktInfo *data.BucketInfo, obj string) string {
	return bktInfo.Name + obj
}

func lockObjectKey(objVersion *ObjectVersion) string {
	// todo reconsider forming name since versionID can be "null" or ""
	return ".lock." + objVersion.BktInfo.CID.EncodeToString() + "." + objVersion.ObjectName + "." + objVersion.VersionID
}

func (n *layer) GetBucketSettings(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	systemKey := systemObjectKey(bktInfo, bktInfo.SettingsObjectName())
	if settings := n.systemCache.GetSettings(systemKey); settings != nil {
		return settings, nil
	}

	settings, err := n.treeService.GetSettingsNode(ctx, bktInfo.CID)
	if err != nil {
		if !errorsStd.Is(err, ErrNodeNotFound) {
			return nil, err
		}
		settings = &data.BucketSettings{}
		settings.IsNoneStatus = true
	}

	if err = n.systemCache.PutSettings(systemKey, settings); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.String("bucket id", bktInfo.CID.EncodeToString()),
			zap.Error(err))
	}

	return settings, nil
}

func (n *layer) PutBucketSettings(ctx context.Context, p *PutSettingsParams) error {
	if err := n.treeService.PutSettingsNode(ctx, p.BktInfo.CID, p.Settings); err != nil {
		return fmt.Errorf("failed to get settings node: %w", err)
	}

	systemKey := systemObjectKey(p.BktInfo, p.BktInfo.SettingsObjectName())
	if err := n.systemCache.PutSettings(systemKey, p.Settings); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) attributesFromLock(ctx context.Context, lock *data.ObjectLock) ([][2]string, error) {
	if lock.Retention == nil {
		return nil, nil
	}

	_, exp, err := n.neoFS.TimeToEpoch(ctx, lock.Retention.Until)
	if err != nil {
		return nil, fmt.Errorf("fetch time to epoch: %w", err)
	}

	result := [][2]string{
		{AttributeExpirationEpoch, strconv.FormatUint(exp, 10)},
	}

	if lock.Retention.IsCompliance {
		attrCompliance := [2]string{
			AttributeComplianceMode, strconv.FormatBool(true),
		}
		result = append(result, attrCompliance)
	}
	return result, nil
}
