package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/notifications"
	"go.uber.org/zap"
)

type (
	PutBucketNotificationConfigurationParams struct {
		RequestInfo *api.ReqInfo
		BktInfo     *data.BucketInfo
		Reader      io.Reader
	}
	SendNotificationsParams struct {
		Event   string
		ObjInfo *data.ObjectInfo
		BktInfo *data.BucketInfo
		ReqInfo *api.ReqInfo
	}
)

func (n *layer) PutBucketNotificationConfiguration(ctx context.Context, p *PutBucketNotificationConfigurationParams) error {
	if !n.IsNotificationEnabled() {
		return errors.GetAPIError(errors.ErrNotificationNotEnabled)
	}

	var (
		buf       bytes.Buffer
		tee       = io.TeeReader(p.Reader, &buf)
		conf      = &data.NotificationConfiguration{}
		completed bool
		err       error
	)

	if err = xml.NewDecoder(tee).Decode(conf); err != nil {
		return errors.GetAPIError(errors.ErrMalformedXML)
	}

	if completed, err = n.checkAndCompleteNotificationConfiguration(conf, p.RequestInfo); err != nil {
		return err
	}
	if completed {
		confXML, err := xml.Marshal(conf)
		if err != nil {
			return err
		}
		buf.Reset()
		buf.Write(confXML)
	}

	s := &PutSystemObjectParams{
		BktInfo:  p.BktInfo,
		ObjName:  p.BktInfo.NotificationConfigurationObjectName(),
		Metadata: map[string]string{},
		Prefix:   "",
		Reader:   &buf,
	}

	obj, err := n.putSystemObjectIntoNeoFS(ctx, s)
	if err != nil {
		return err
	}

	if obj.Size == 0 && !conf.IsEmpty() {
		return errors.GetAPIError(errors.ErrInternalError)
	}

	if err = n.systemCache.PutNotificationConfiguration(systemObjectKey(p.BktInfo, s.ObjName), conf); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) GetBucketNotificationConfiguration(ctx context.Context, bktInfo *data.BucketInfo) (*data.NotificationConfiguration, error) {
	if !n.IsNotificationEnabled() {
		return nil, errors.GetAPIError(errors.ErrNotificationNotEnabled)
	}
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
		return nil, err
	}

	if err = n.systemCache.PutNotificationConfiguration(systemObjectKey(bkt, sysName), conf); err != nil {
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", obj.ID()),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}

	return conf, nil
}

func (n *layer) checkAndCompleteNotificationConfiguration(c *data.NotificationConfiguration, r *api.ReqInfo) (completed bool, err error) {
	if c == nil {
		return
	}

	if c.TopicConfigurations != nil || c.LambdaFunctionConfigurations != nil {
		return completed, errors.GetAPIError(errors.ErrNotificationTopicNotSupported)
	}

	e := prepareTestEvent(r.BucketName, r.RequestID, r.Host)

	for i, q := range c.QueueConfigurations {
		if err = checkEvents(q.Events); err != nil {
			return
		}
		if err = checkRules(q.Filter.Key.FilterRules); err != nil {
			return
		}
		if err = n.ncontroller.SendTestEvent(e, q.QueueArn); err != nil {
			return
		}
		if q.ID == "" {
			completed = true
			c.QueueConfigurations[i].ID = uuid.NewString()
		}
	}

	return
}

func checkEvents(events []string) error {
	for _, e := range events {
		if _, ok := data.ValidEvents[e]; !ok {
			return errors.GetAPIError(errors.ErrEventNotification)
		}
	}

	return nil
}

func checkRules(rules []data.FilterRule) error {
	names := make(map[string]struct{})

	for _, r := range rules {
		if r.Name != "suffix" && r.Name != "prefix" {
			return errors.GetAPIError(errors.ErrFilterNameInvalid)
		}
		if _, ok := names[r.Name]; ok {
			if r.Name == "suffix" {
				return errors.GetAPIError(errors.ErrFilterNameSuffix)
			}
			return errors.GetAPIError(errors.ErrFilterNamePrefix)
		}

		names[r.Name] = struct{}{}
	}

	return nil
}

func prepareTestEvent(bktName, requestID, host string) *notifications.TestEvent {
	return &notifications.TestEvent{
		Service: "NeoFS S3",
		Event:   "s3:TestEvent",
		// Time field value will be placed later
		Bucket:    bktName,
		RequestID: requestID,
		HostID:    host,
	}
}
func prepareEvent(eventName string, bkt *data.BucketInfo, obj *data.ObjectInfo, reqInfo *api.ReqInfo) *notifications.Event {
	return &notifications.Event{
		Records: []notifications.EventRecord{
			{
				EventVersion: notifications.EventVersion21,
				EventSource:  "neofs:s3",
				AWSRegion:    "",
				EventTime:    obj.Created,
				EventName:    eventName,
				UserIdentity: notifications.UserIdentity{
					PrincipalID: obj.Owner.String(),
				},
				RequestParameters: notifications.RequestParameters{
					SourceIPAddress: reqInfo.RemoteHost,
				},
				ResponseElements: nil,
				S3: notifications.S3Entity{
					SchemaVersion: "1.0",
					// ConfigurationID is skipped and will be placed later
					Bucket: notifications.Bucket{
						Name:          bkt.Name,
						OwnerIdentity: notifications.UserIdentity{PrincipalID: bkt.Owner.String()},
						Arn:           "",
					},
					Object: notifications.Object{
						Key:       obj.Name,
						Size:      obj.Size,
						VersionID: obj.Version(),
						ETag:      obj.HashSum,
						Sequencer: "",
					},
				},
			},
		},
	}
}

func (n *layer) SendNotifications(ctx context.Context, p *SendNotificationsParams) error {
	if n.IsNotificationEnabled() {
		conf, err := n.getNotificationConf(ctx, p.BktInfo, p.BktInfo.NotificationConfigurationObjectName())
		if err != nil {
			return err
		}
		if conf.IsEmpty() {
			return nil
		}

		topics := conf.FilterTopics(p.Event, p.ObjInfo.Name)

		if len(topics) != 0 {
			event := prepareEvent(p.Event, p.BktInfo, p.ObjInfo, p.ReqInfo)

			for id, topic := range topics {
				if err := n.ncontroller.SendEvent(event, id, topic); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
