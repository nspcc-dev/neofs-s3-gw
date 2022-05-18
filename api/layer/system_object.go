package layer

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	errorsStd "errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/internal/misc"
	"github.com/nspcc-dev/neofs-sdk-go/object"
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

	node, err := n.treeService.GetSystemVersion(ctx, &bkt.CID, objName)
	if err != nil {
		if errorsStd.Is(err, ErrNodeNotFound) {
			return nil, errors.GetAPIError(errors.ErrNoSuchKey)
		}
		return nil, err
	}

	meta, err := n.objectHead(ctx, bkt, node.OID)
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
		bkt:  bktInfo,
	}
	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return err
	}

	n.systemCache.Delete(systemObjectKey(bktInfo, name))
	for i := range ids {
		if err = n.objectDelete(ctx, bktInfo, ids[i]); err != nil {
			return err
		}
	}

	return nil
}

func (n *layer) putSystemObjectIntoNeoFS(ctx context.Context, p *PutSystemObjectParams) (*data.ObjectInfo, error) {
	prm := PrmObjectCreate{
		Container:  p.BktInfo.CID,
		Creator:    p.BktInfo.Owner,
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

	id, hash, err := n.objectPutAndHash(ctx, prm, p.BktInfo)
	if err != nil {
		return nil, err
	}

	newVersion := &BaseNodeVersion{OID: *id}
	if err = n.treeService.AddSystemVersion(ctx, &p.BktInfo.CID, p.ObjName, newVersion); err != nil {
		return nil, fmt.Errorf("couldn't add new verion to tree service: %w", err)
	}

	currentEpoch, _, err := n.neoFS.TimeToEpoch(ctx, time.Now().Add(time.Minute))
	if err != nil {
		n.log.Warn("couldn't get creation epoch",
			zap.String("bucket", p.BktInfo.Name),
			zap.String("object", misc.SanitizeString(p.ObjName)),
			zap.Error(err))
	}

	headers := make(map[string]string, len(p.Metadata))
	for _, attr := range prm.Attributes {
		headers[attr[0]] = attr[1]
	}

	return &data.ObjectInfo{
		ID:  *id,
		CID: p.BktInfo.CID,

		Owner:         p.BktInfo.Owner,
		Bucket:        p.BktInfo.Name,
		Name:          p.ObjName,
		Created:       time.Now(),
		CreationEpoch: currentEpoch,
		Size:          p.Size,
		Headers:       headers,
		HashSum:       hex.EncodeToString(hash),
	}, nil
}

func (n *layer) getSystemObjectFromNeoFS(ctx context.Context, bkt *data.BucketInfo, objName string) (*object.Object, error) {
	versions, err := n.headSystemVersions(ctx, bkt, objName)
	if err != nil {
		return nil, err
	}

	objInfo := versions.getLast()

	obj, err := n.objectGet(ctx, bkt, objInfo.ID)
	if err != nil {
		return nil, err
	}

	if len(obj.Payload()) == 0 {
		return nil, errors.GetAPIError(errors.ErrInternalError)
	}
	return obj, nil
}

func (n *layer) getCORS(ctx context.Context, bkt *data.BucketInfo, sysName string) (*data.CORSConfiguration, error) {
	if cors := n.systemCache.GetCORS(systemObjectKey(bkt, sysName)); cors != nil {
		return cors, nil
	}
	objID, err := n.treeService.GetBucketCORS(ctx, &bkt.CID)
	if err != nil {
		return nil, err
	}

	if objID == nil {
		return nil, errors.GetAPIError(errors.ErrNoSuchCORSConfiguration)
	}

	obj, err := n.objectGet(ctx, bkt, *objID)
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

func (n *layer) headSystemVersions(ctx context.Context, bkt *data.BucketInfo, sysName string) (*objectVersions, error) {
	f := &findParams{
		attr: [2]string{objectSystemAttributeName, sysName},
		bkt:  bkt,
	}
	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}

	versions := newObjectVersions(sysName)
	for i := range ids {
		meta, err := n.objectHead(ctx, bkt, ids[i])
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", &ids[i]),
				zap.Stringer("bucket id", bkt.CID),
				zap.Error(err))
			continue
		}

		if oi := objInfoFromMeta(bkt, meta); oi != nil {
			if !isSystem(oi) {
				continue
			}
			versions.appendVersion(oi)
		}
	}

	lastVersion := versions.getLast()
	if lastVersion == nil {
		return nil, errors.GetAPIError(errors.ErrNoSuchKey)
	}

	return versions, nil
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

	settings, err := n.treeService.GetSettingsNode(ctx, &bktInfo.CID)
	if err != nil {
		if !errorsStd.Is(err, ErrNodeNotFound) {
			return nil, err
		}
		settings = &data.BucketSettings{}
		settings.IsNoneStatus = true
	}

	if err = n.systemCache.PutSettings(systemKey, settings); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("bucket id", bktInfo.CID),
			zap.Error(err))
	}

	return settings, nil
}

func (n *layer) PutBucketSettings(ctx context.Context, p *PutSettingsParams) error {
	if err := n.treeService.PutSettingsNode(ctx, &p.BktInfo.CID, p.Settings); err != nil {
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
