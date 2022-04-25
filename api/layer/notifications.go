package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
)

type (
	PutBucketNotificationConfigurationParams struct {
		RequestInfo *api.ReqInfo
		BktInfo     *data.BucketInfo
		Reader      io.Reader
	}

	SendNotificationParams struct {
		Event   string
		ObjInfo *data.ObjectInfo
		BktInfo *data.BucketInfo
		ReqInfo *api.ReqInfo
		User    string
	}
)

const (
	filterRuleSuffixName = "suffix"
	filterRulePrefixName = "prefix"

	EventObjectCreated                                = "s3:ObjectCreated:*"
	EventObjectCreatedPut                             = "s3:ObjectCreated:Put"
	EventObjectCreatedPost                            = "s3:ObjectCreated:Post"
	EventObjectCreatedCopy                            = "s3:ObjectCreated:Copy"
	EventReducedRedundancyLostObject                  = "s3:ReducedRedundancyLostObject"
	EventObjectCreatedCompleteMultipartUpload         = "s3:ObjectCreated:CompleteMultipartUpload"
	EventObjectRemoved                                = "s3:ObjectRemoved:*"
	EventObjectRemovedDelete                          = "s3:ObjectRemoved:Delete"
	EventObjectRemovedDeleteMarkerCreated             = "s3:ObjectRemoved:DeleteMarkerCreated"
	EventObjectRestore                                = "s3:ObjectRestore:*"
	EventObjectRestorePost                            = "s3:ObjectRestore:Post"
	EventObjectRestoreCompleted                       = "s3:ObjectRestore:Completed"
	EventReplication                                  = "s3:Replication:*"
	EventReplicationOperationFailedReplication        = "s3:Replication:OperationFailedReplication"
	EventReplicationOperationNotTracked               = "s3:Replication:OperationNotTracked"
	EventReplicationOperationMissedThreshold          = "s3:Replication:OperationMissedThreshold"
	EventReplicationOperationReplicatedAfterThreshold = "s3:Replication:OperationReplicatedAfterThreshold"
	EventObjectRestoreDelete                          = "s3:ObjectRestore:Delete"
	EventLifecycleTransition                          = "s3:LifecycleTransition"
	EventIntelligentTiering                           = "s3:IntelligentTiering"
	EventObjectACLPut                                 = "s3:ObjectAcl:Put"
	EventLifecycleExpiration                          = "s3:LifecycleExpiration:*"
	EventLifecycleExpirationDelete                    = "s3:LifecycleExpiration:Delete"
	EventLifecycleExpirationDeleteMarkerCreated       = "s3:LifecycleExpiration:DeleteMarkerCreated"
	EventObjectTagging                                = "s3:ObjectTagging:*"
	EventObjectTaggingPut                             = "s3:ObjectTagging:Put"
	EventObjectTaggingDelete                          = "s3:ObjectTagging:Delete"
)

var validEvents = map[string]struct{}{
	EventReducedRedundancyLostObject:                  {},
	EventObjectCreated:                                {},
	EventObjectCreatedPut:                             {},
	EventObjectCreatedPost:                            {},
	EventObjectCreatedCopy:                            {},
	EventObjectCreatedCompleteMultipartUpload:         {},
	EventObjectRemoved:                                {},
	EventObjectRemovedDelete:                          {},
	EventObjectRemovedDeleteMarkerCreated:             {},
	EventObjectRestore:                                {},
	EventObjectRestorePost:                            {},
	EventObjectRestoreCompleted:                       {},
	EventReplication:                                  {},
	EventReplicationOperationFailedReplication:        {},
	EventReplicationOperationNotTracked:               {},
	EventReplicationOperationMissedThreshold:          {},
	EventReplicationOperationReplicatedAfterThreshold: {},
	EventObjectRestoreDelete:                          {},
	EventLifecycleTransition:                          {},
	EventIntelligentTiering:                           {},
	EventObjectACLPut:                                 {},
	EventLifecycleExpiration:                          {},
	EventLifecycleExpirationDelete:                    {},
	EventLifecycleExpirationDeleteMarkerCreated:       {},
	EventObjectTagging:                                {},
	EventObjectTaggingPut:                             {},
	EventObjectTaggingDelete:                          {},
}

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

	if completed, err = n.checkBucketConfiguration(conf, p.RequestInfo); err != nil {
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
		objID, _ := obj.ID()
		n.log.Warn("couldn't put system meta to objects cache",
			zap.Stringer("object id", &objID),
			zap.Stringer("bucket id", bkt.CID),
			zap.Error(err))
	}

	return conf, nil
}

func (n *layer) SendNotifications(ctx context.Context, p *SendNotificationParams) error {
	if !n.IsNotificationEnabled() {
		return nil
	}

	conf, err := n.getNotificationConf(ctx, p.BktInfo, p.BktInfo.NotificationConfigurationObjectName())
	if err != nil {
		return err
	}
	if conf.IsEmpty() {
		return nil
	}

	box, err := GetBoxData(ctx)
	if err == nil {
		p.User = box.Gate.BearerToken.OwnerID().String()
	}

	topics := filterSubjects(conf, p.Event, p.ObjInfo.Name)

	return n.ncontroller.SendNotifications(topics, p)
}

// checkBucketConfiguration checks notification configuration and generates an ID for configurations with empty ids.
func (n *layer) checkBucketConfiguration(conf *data.NotificationConfiguration, r *api.ReqInfo) (completed bool, err error) {
	if conf == nil {
		return
	}

	if conf.TopicConfigurations != nil || conf.LambdaFunctionConfigurations != nil {
		return completed, errors.GetAPIError(errors.ErrNotificationTopicNotSupported)
	}

	for i, q := range conf.QueueConfigurations {
		if err = checkEvents(q.Events); err != nil {
			return
		}

		if err = checkRules(q.Filter.Key.FilterRules); err != nil {
			return
		}

		if err = n.ncontroller.SendTestNotification(q.QueueArn, r.BucketName, r.RequestID, r.Host); err != nil {
			return
		}

		if q.ID == "" {
			completed = true
			conf.QueueConfigurations[i].ID = uuid.NewString()
		}
	}

	return
}

func filterSubjects(conf *data.NotificationConfiguration, eventType, objName string) map[string]string {
	topics := make(map[string]string)

	for _, t := range conf.QueueConfigurations {
		event := false
		for _, e := range t.Events {
			// the second condition is comparison with the events ending with *:
			// s3:ObjectCreated:*, s3:ObjectRemoved:* etc without the last char
			if eventType == e || strings.HasPrefix(eventType, e[:len(e)-1]) {
				event = true
				break
			}
		}

		if !event {
			continue
		}

		filter := true
		for _, f := range t.Filter.Key.FilterRules {
			if f.Name == filterRulePrefixName && !strings.HasPrefix(objName, f.Value) ||
				f.Name == filterRuleSuffixName && !strings.HasSuffix(objName, f.Value) {
				filter = false
				break
			}
		}
		if filter {
			topics[t.ID] = t.QueueArn
		}
	}

	return topics
}

func checkRules(rules []data.FilterRule) error {
	names := make(map[string]struct{})

	for _, r := range rules {
		if r.Name != filterRuleSuffixName && r.Name != filterRulePrefixName {
			return errors.GetAPIError(errors.ErrFilterNameInvalid)
		}
		if _, ok := names[r.Name]; ok {
			if r.Name == filterRuleSuffixName {
				return errors.GetAPIError(errors.ErrFilterNameSuffix)
			}
			return errors.GetAPIError(errors.ErrFilterNamePrefix)
		}

		names[r.Name] = struct{}{}
	}

	return nil
}

func checkEvents(events []string) error {
	for _, e := range events {
		if _, ok := validEvents[e]; !ok {
			return errors.GetAPIError(errors.ErrEventNotification)
		}
	}

	return nil
}
