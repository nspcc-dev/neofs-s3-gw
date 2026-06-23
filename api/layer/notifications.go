package layer

import (
	"context"
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

	n.cache.DeleteBucket(p.BktInfo.Name, p.BktInfo.Namespace)

	return nil
}

func (n *layer) GetBucketNotificationConfiguration(_ context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	return bktInfo.Notifications, nil
}
