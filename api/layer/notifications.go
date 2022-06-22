package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
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
		return fmt.Errorf("marshal notify configuration: %w", err)
	}

	s := &PutSystemObjectParams{
		BktInfo:  p.BktInfo,
		ObjName:  p.BktInfo.NotificationConfigurationObjectName(),
		Metadata: map[string]string{},
		Reader:   bytes.NewReader(confXML),
		Size:     int64(len(confXML)),
	}

	_, err = n.putSystemObjectIntoNeoFS(ctx, s)
	if err != nil {
		return err
	}

	if err = n.systemCache.PutNotificationConfiguration(systemObjectKey(p.BktInfo, s.ObjName), p.Configuration); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	conf, err := n.getNotificationConf(ctx, bktInfo, bktInfo.NotificationConfigurationObjectName())
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchKey) {
			return &data.NotificationConfiguration{}, nil
		}
		return nil, err
	}

	return conf, nil
}

func (n *layer) getNotificationConf(ctx context.Context, bkt *data.BucketInfo, sysName string) (*data.NotificationConfiguration, error) {
	if conf := n.systemCache.GetNotificationConfiguration(systemObjectKey(bkt, sysName)); conf != nil {
		return conf, nil
	}

	obj, err := n.getSystemObjectFromNeoFS(ctx, bkt, sysName)
	if err != nil {
		return nil, err
	}

	conf := &data.NotificationConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &conf); err != nil {
		return nil, fmt.Errorf("unmarshal notify configuration: %w", err)
	}

	if err = n.systemCache.PutNotificationConfiguration(systemObjectKey(bkt, sysName), conf); err != nil {
		objID, _ := obj.ID()
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", &objID),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}

	return conf, nil
}
