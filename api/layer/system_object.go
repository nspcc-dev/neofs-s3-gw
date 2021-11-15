package layer

import (
	"context"
	"encoding/xml"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/object"
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
	ids, err := n.objectSearch(ctx, &findParams{cid: bktInfo.CID, attr: objectSystemAttributeName, val: name})
	if err != nil {
		return err
	}

	for _, id := range ids {
		if err = n.objectDelete(ctx, bktInfo.CID, id); err != nil {
			return err
		}
	}

	n.systemCache.Delete(systemObjectKey(bktInfo, name))
	return nil
}

func (n *layer) putSystemObjectIntoNeoFS(ctx context.Context, p *PutSystemObjectParams) (*data.ObjectInfo, error) {
	versions, err := n.headSystemVersions(ctx, p.BktInfo, p.ObjName)
	if err != nil && !errors.IsS3Error(err, errors.ErrNoSuchKey) {
		return nil, err
	}
	idsToDeleteArr := updateCRDT2PSetHeaders(p.Metadata, versions, false) // false means "last write wins"

	attributes := make([]*object.Attribute, 0, 3)

	filename := object.NewAttribute()
	filename.SetKey(objectSystemAttributeName)
	filename.SetValue(p.ObjName)

	createdAt := object.NewAttribute()
	createdAt.SetKey(object.AttributeTimestamp)
	createdAt.SetValue(strconv.FormatInt(time.Now().UTC().Unix(), 10))

	versioningIgnore := object.NewAttribute()
	versioningIgnore.SetKey(attrVersionsIgnore)
	versioningIgnore.SetValue(strconv.FormatBool(true))

	attributes = append(attributes, filename, createdAt, versioningIgnore)

	for k, v := range p.Metadata {
		attr := object.NewAttribute()
		attr.SetKey(p.Prefix + k)
		if p.Prefix == tagPrefix && v == "" {
			v = tagEmptyMark
		}
		attr.SetValue(v)
		attributes = append(attributes, attr)
	}

	raw := object.NewRaw()
	raw.SetOwnerID(p.BktInfo.Owner)
	raw.SetContainerID(p.BktInfo.CID)
	raw.SetAttributes(attributes...)

	ops := new(client.PutObjectParams).WithObject(raw.Object()).WithPayloadReader(p.Reader)
	oid, err := n.pool.PutObject(ctx, ops, n.CallOptions(ctx)...)
	if err != nil {
		return nil, err
	}

	meta, err := n.objectHead(ctx, p.BktInfo.CID, oid)
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

	obj, err := n.objectGet(ctx, bkt.CID, objInfo.ID)
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
	ids, err := n.objectSearch(ctx, &findParams{cid: bkt.CID, attr: objectSystemAttributeName, val: sysName})
	if err != nil {
		return nil, err
	}

	versions := newObjectVersions(sysName)
	for _, id := range ids {
		meta, err := n.objectHead(ctx, bkt.CID, id)
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("object id", id),
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
