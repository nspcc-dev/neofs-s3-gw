package layer

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	"go.uber.org/zap"
)

func (n *layer) putSystemObject(ctx context.Context, p *PutSystemObjectParams) (*data.ObjectInfo, error) {
	objInfo, err := n.putSystemObjectIntoNeoFS(ctx, p)
	if err != nil {
		return nil, err
	}

	if err = n.systemCache.PutObject(systemObjectKey(p.BktInfo, p.ObjName), objInfo); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return objInfo, nil
}

func (n *layer) headSystemObject(ctx context.Context, bkt *data.BucketInfo, objName string) (*data.ObjectInfo, error) {
	if objInfo := n.systemCache.GetObject(systemObjectKey(bkt, objName)); objInfo != nil {
		return objInfo, nil
	}

	versions, err := n.headSystemVersions(ctx, bkt, objName)
	if err != nil {
		return nil, err
	}

	if err = n.systemCache.PutObject(systemObjectKey(bkt, objName), versions.getLast()); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return versions.getLast(), nil
}

func (n *layer) deleteSystemObject(ctx context.Context, bktInfo *data.BucketInfo, name string) error {
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
	versions, err := n.headSystemVersions(ctx, p.BktInfo, p.ObjName)
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}

	idsToDeleteArr := updateCRDT2PSetHeaders(p.Metadata, versions, false) // false means "last write wins"
	// note that updateCRDT2PSetHeaders modifies p.Metadata and must be called further processing

	prm := PrmObjectCreate{
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

		prm.Attributes = append(prm.Attributes, [2]string{k, v})
	}

	id, err := n.neoFS.CreateObject(ctx, prm)
	if err != nil {
		return nil, n.transformNeofsError(ctx, err)
	}

	meta, err := n.objectHead(ctx, p.BktInfo.CID, id)
	if err != nil {
		return nil, err
	}

	for _, id := range idsToDeleteArr {
		if err = n.objectDelete(ctx, p.BktInfo.CID, id); err != nil {
			n.log.Warn("couldn't delete system object",
				zap.Stringer("version id", id),
				zap.String("name", p.ObjName),
				zap.Error(err))
		}
	}

	return objInfoFromMeta(p.BktInfo, meta), nil
}

func (n *layer) getSystemObjectFromNeoFS(ctx context.Context, bkt *data.BucketInfo, objName string) (*object.Object, error) {
	versions, err := n.headSystemVersions(ctx, bkt, objName)
	if err != nil {
		return nil, err
	}

	objInfo := versions.getLast()

	var addr address.Address

	addr.SetContainerID(bkt.CID)
	addr.SetObjectID(objInfo.ID)

	obj, err := n.objectGet(ctx, &addr)
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

	obj, err := n.getSystemObjectFromNeoFS(ctx, bkt, sysName)
	if err != nil {
		return nil, err
	}

	cors := &data.CORSConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &cors); err != nil {
		return nil, err
	}

	if err = n.systemCache.PutCORS(systemObjectKey(bkt, sysName), cors); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", obj.ID()),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}

	return cors, nil
}

func (n *layer) headSystemVersions(ctx context.Context, bkt *data.BucketInfo, sysName string) (*objectVersions, error) {
	f := &findParams{
		attr: [2]string{objectSystemAttributeName, sysName},
		cid:  bkt.CID,
	}
	ids, err := n.objectSearch(ctx, f)
	if err != nil {
		return nil, err
	}

	versions := newObjectVersions(sysName)
	for i := range ids {
		meta, err := n.objectHead(ctx, bkt.CID, &ids[i])
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
	if settings := n.systemCache.GetSettings(bktInfo.SettingsObjectName()); settings != nil {
		return settings, nil
	}

	obj, err := n.getSystemObjectFromNeoFS(ctx, bktInfo, bktInfo.SettingsObjectName())
	if err != nil {
		return nil, err
	}

	settings := &data.BucketSettings{}
	if err = json.Unmarshal(obj.Payload(), settings); err != nil {
		return nil, err
	}

	if err = n.systemCache.PutSettings(bktInfo.SettingsObjectName(), settings); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", obj.ID()),
			zap.Stringer("bucket id", bktInfo.CID),
			zap.Error(err))
	}

	return settings, nil
}

func (n *layer) PutBucketSettings(ctx context.Context, p *PutSettingsParams) error {
	rawSettings, err := json.Marshal(p.Settings)
	if err != nil {
		return fmt.Errorf("couldn't marshal bucket settings")
	}

	s := &PutSystemObjectParams{
		BktInfo:  p.BktInfo,
		ObjName:  p.BktInfo.SettingsObjectName(),
		Metadata: map[string]string{},
		Reader:   bytes.NewReader(rawSettings),
	}

	obj, err := n.putSystemObjectIntoNeoFS(ctx, s)
	if err != nil {
		return err
	}

	if obj.Size == 0 {
		return errors.GetAPIError(errors.ErrInternalError)
	}

	if err = n.systemCache.PutSettings(p.BktInfo.SettingsObjectName(), p.Settings); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}
