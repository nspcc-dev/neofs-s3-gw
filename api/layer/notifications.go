package layer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
)

type PutBucketNotificationConfigurationParams struct {
	RequestInfo   *api.ReqInfo
	BktInfo       *data.BucketInfo
	Configuration *data.NotificationConfiguration
}

func (n *layer) PutBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error {
	var sessionTokenV2 *session.Token
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionTokenV2 = boxData.Gate.SessionTokenV2
	}

	if err = n.storeAttribute(ctx, p.BktInfo.CID, attributeNotifications, p.Configuration, sessionTokenV2); err != nil {
		return fmt.Errorf("store bucket notification settings: %w", err)
	}

	n.cache.PutNotificationConfiguration(n.Owner(ctx), p.BktInfo, p.Configuration)
	n.cache.DeleteBucket(p.BktInfo.Name)

	return nil
}

func (n *layer) GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	owner := n.Owner(ctx)
	if conf := n.cache.GetNotificationConfiguration(owner, bktInfo); conf != nil {
		return conf, nil
	}

	var conf = &data.NotificationConfiguration{}
	if bktInfo.AttributeNotifications != "" {
		if err := json.Unmarshal([]byte(bktInfo.AttributeNotifications), conf); err != nil {
			return nil, fmt.Errorf("malformed data: %w", err)
		}
	}

	n.cache.PutNotificationConfiguration(owner, bktInfo, conf)
	return conf, nil
}
