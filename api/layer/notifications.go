package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	errorsStd "errors"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"go.uber.org/zap"
)

type PutBucketNotificationConfigurationParams struct {
	RequestInfo   *api.ReqInfo
	BktInfo       *data.BucketInfo
	Configuration *data.NotificationConfiguration
}

func (n *layer) PutBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error {
	confXML, err := xml.Marshal(p.Configuration)
	if err != nil {
		return err
	}

	sysName := p.BktInfo.NotificationConfigurationObjectName()

	s := &PutSystemObjectParams{
		BktInfo:  p.BktInfo,
		ObjName:  sysName,
		Metadata: map[string]string{},
		Reader:   bytes.NewReader(confXML),
	}

	obj, err := n.putSystemObjectIntoNeoFS(ctx, s)
	if err != nil {
		return err
	}

	objIDToDelete, err := n.treeService.PutNotificationConfigurationNode(ctx, &p.BktInfo.CID, &obj.ID)
	if err != nil {
		return err
	}

	if objIDToDelete != nil {
		if err = n.objectDelete(ctx, p.BktInfo.CID, *objIDToDelete); err != nil {
			n.log.Error("couldn't delete notification configuration object", zap.Error(err),
				zap.String("cnrID", p.BktInfo.CID.EncodeToString()),
				zap.String("bucket name", p.BktInfo.Name),
				zap.String("objID", objIDToDelete.EncodeToString()))
		}
	}

	if err = n.systemCache.PutNotificationConfiguration(systemObjectKey(p.BktInfo, sysName), p.Configuration); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	systemCacheKey := systemObjectKey(bktInfo, bktInfo.NotificationConfigurationObjectName())

	if conf := n.systemCache.GetNotificationConfiguration(systemCacheKey); conf != nil {
		return conf, nil
	}

	objId, err := n.treeService.GetNotificationConfigurationNode(ctx, &bktInfo.CID)
	if err != nil && !errorsStd.Is(err, ErrNodeNotFound) {
		return nil, err
	}

	conf := &data.NotificationConfiguration{}

	if objId != nil {
		var addr oid.Address
		addr.SetContainer(bktInfo.CID)
		addr.SetObject(*objId)

		obj, err := n.objectGet(ctx, addr)
		if err != nil {
			return nil, err
		}

		if err = xml.Unmarshal(obj.Payload(), &conf); err != nil {
			return nil, err
		}
	}

	if err = n.systemCache.PutNotificationConfiguration(systemCacheKey, conf); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("bucket id", bktInfo.CID),
			zap.Error(err))
	}

	return conf, nil
}
