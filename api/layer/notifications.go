package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
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

	prm := PrmObjectCreate{
		Container:    p.BktInfo.CID,
		Creator:      p.BktInfo.Owner,
		Payload:      bytes.NewReader(confXML),
		CreationTime: TimeNow(ctx),
		Attributes: map[string]string{
			s3headers.MetaType: s3headers.TypeBucketNotifConfig,
		},
	}

	if _, _, err = n.objectPutAndHash(ctx, prm, p.BktInfo); err != nil {
		return err
	}

	n.cache.PutNotificationConfiguration(n.Owner(ctx), p.BktInfo, p.Configuration)

	return nil
}

func (n *layer) GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	owner := n.Owner(ctx)
	if conf := n.cache.GetNotificationConfiguration(owner, bktInfo); conf != nil {
		return conf, nil
	}

	var (
		err  error
		conf data.NotificationConfiguration
	)

	id, err := n.searchBucketMetaObjects(ctx, bktInfo, s3headers.TypeBucketNotifConfig)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	if id.IsZero() {
		return &conf, nil
	}

	obj, err := n.objectGet(ctx, bktInfo, id)
	if err != nil {
		return nil, err
	}

	if err = xml.Unmarshal(obj.Payload(), &conf); err != nil {
		return nil, fmt.Errorf("unmarshal notify configuration: %w", err)
	}

	n.cache.PutNotificationConfiguration(n.Owner(ctx), bktInfo, &conf)

	return &conf, nil
}
