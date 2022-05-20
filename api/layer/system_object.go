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
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	"go.uber.org/zap"
)

const (
	AttributeComplianceMode  = ".s3-compliance-mode"
	AttributeRetainUntil     = ".s3-retain-until"
	AttributeExpirationEpoch = "__NEOFS__EXPIRATION_EPOCH"
	AttributeSysTickEpoch    = "__NEOFS__TICK_EPOCH"
	AttributeSysTickTopic    = "__NEOFS__TICK_TOPIC"
)

func (n *layer) PutSystemObject(ctx context.Context, p *PutSystemObjectParams) (*data.ObjectInfo, error) {
	objInfo, err := n.putSystemObjectIntoNeoFS(ctx, p)
	if err != nil {
		return nil, err
	}

	if err = n.systemCache.PutObject(systemObjectKey(p.BktInfo, p.ObjName), objInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return objInfo, nil
}

func (n *layer) HeadSystemObject(ctx context.Context, bkt *data.BucketInfo, objName string) (*data.ObjectInfo, error) {
	if objInfo := n.systemCache.GetObject(systemObjectKey(bkt, objName)); objInfo != nil {
		return objInfo, nil
	}

	node, err := n.treeService.GetSystemVersion(ctx, bkt.CID, objName)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, err
	}

	meta, err := n.objectHead(ctx, bkt.CID, node.OID)
	if err != nil {
		return nil, err
	}

	objInfo := objInfoFromMeta(bkt, meta)
	if err = n.systemCache.PutObject(systemObjectKey(bkt, objName), objInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return objInfo, nil
}

func (n *layer) DeleteSystemObject(ctx context.Context, bktInfo *data.BucketInfo, name string) error {
	f := &findParams{
		attr: [2]string{objectSystemAttributeName, name},
		cid:  bktInfo.CID,
	}
	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return err
	}

	n.systemCache.Delete(systemObjectKey(bktInfo, name))
	for i := range ids {
		if err = n.objectDelete(ctx, bktInfo.CID, &ids[i]); err != nil {
			return err
		}
	}

	return nil
}

func (n *layer) putSystemObjectIntoNeoFS(ctx context.Context, p *PutSystemObjectParams) (*data.ObjectInfo, error) {
	prm := neofs.PrmObjectCreate{
		Container:  *p.BktInfo.CID,
		Creator:    *p.BktInfo.Owner,
		Attributes: make([][2]string, 2, 2+len(p.Metadata)),
		Payload:    p.Reader,
	}

	prm.Attributes[0][0], prm.Attributes[0][1] = objectSystemAttributeName, p.ObjName
	prm.Attributes[1][0], prm.Attributes[1][1] = attrVersionsIgnore, "true"

	for k, v := range p.Metadata {
		if !IsSystemHeader(k) {
			k = p.Prefix + k
		}

		if v == "" && p.Prefix == tagPrefix {
			v = tagEmptyMark
		}

		if p.Lock != nil && len(p.Lock.Objects) > 0 {
			prm.Locks = p.Lock.Objects

			attrs, err := n.attributesFromLock(ctx, p.Lock)
			if err != nil {
				return nil, err
			}

			prm.Attributes = append(prm.Attributes, attrs...)
		}

		prm.Attributes = append(prm.Attributes, [2]string{k, v})
	}

	id, err := n.objectPut(ctx, prm)
	if err != nil {
		return nil, err
	}

	newVersion := &data.BaseNodeVersion{OID: *id}
	if err = n.treeService.AddSystemVersion(ctx, p.BktInfo.CID, p.ObjName, newVersion); err != nil {
		return nil, fmt.Errorf("couldn't add new verion to tree service: %w", err)
	}

	meta, err := n.objectHead(ctx, p.BktInfo.CID, *id)
	if err != nil {
		return nil, err
	}

	return objInfoFromMeta(p.BktInfo, meta), nil
}

func (n *layer) getCORS(ctx context.Context, bkt *data.BucketInfo, sysName string) (*data.CORSConfiguration, error) {
	if cors := n.systemCache.GetCORS(systemObjectKey(bkt, sysName)); cors != nil {
		return cors, nil
	}
	objID, err := n.treeService.GetBucketCORS(ctx, bkt.CID)
	if err != nil {
		return nil, err
	}

	if objID == nil {
		return nil, errors.GetAPIError(errors.ErrNoSuchCORSConfiguration)
	}

	var addr address.Address
	addr.SetContainerID(*bkt.CID)
	addr.SetObjectID(*objID)

	obj, err := n.objectGet(ctx, &addr)
	if err != nil {
		return nil, err
	}

	cors := &data.CORSConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &cors); err != nil {
		return nil, err
	}

	if err = n.systemCache.PutCORS(systemObjectKey(bkt, sysName), cors); err != nil {
		objID, _ := obj.ID()
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", &objID),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}

	return cors, nil
}

// systemObjectKey is a key to use in SystemCache.
func systemObjectKey(bktInfo *data.BucketInfo, obj string) string {
	return bktInfo.Name + obj
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
	}

	if err = n.systemCache.PutSettings(systemKey, settings); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("bucket id", bktInfo.CID),
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
	var result [][2]string
	if !lock.Until.IsZero() {
		_, exp, err := n.neoFS.TimeToEpoch(ctx, lock.Until)
		if err != nil {
			return nil, err
		}

		attrs := [][2]string{
			{AttributeExpirationEpoch, strconv.FormatUint(exp, 10)},
			{AttributeRetainUntil, lock.Until.Format(time.RFC3339)},
		}

		result = append(result, attrs...)
		if lock.IsCompliance {
			attrCompliance := [2]string{
				AttributeComplianceMode, strconv.FormatBool(true),
			}
			result = append(result, attrCompliance)
		}
	}

	return result, nil
}
