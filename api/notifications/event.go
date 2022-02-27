package notifications

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	// EventVersion23 is used for lifecycle, tiering, objectACL, objectTagging, object restoration notifications.
	EventVersion23 = "2.3"
	// EventVersion22 is used for replication notifications.
	EventVersion22 = "2.2"
	// EventVersion21 is used for all other notification types.
	EventVersion21 = "2.1"
)

type (
	TestEvent struct {
		Service   string
		Event     string
		Time      time.Time
		Bucket    string
		RequestID string
		HostID    string
	}
	Event struct {
		Records []EventRecord `json:"Records"`
	}

	EventRecord struct {
		EventVersion      string            `json:"eventVersion"`
		EventSource       string            `json:"eventSource"`         // neofs:s3
		AWSRegion         string            `json:"awsRegion,omitempty"` // empty
		EventTime         time.Time         `json:"eventTime"`
		EventName         string            `json:"eventName"`
		UserIdentity      UserIdentity      `json:"userIdentity"`
		RequestParameters RequestParameters `json:"requestParameters"`
		ResponseElements  map[string]string `json:"responseElements"`
		S3                S3Entity          `json:"s3"`
	}

	UserIdentity struct {
		PrincipalID string `json:"principalId"`
	}

	RequestParameters struct {
		SourceIPAddress string `json:"sourceIPAddress"`
	}

	S3Entity struct {
		SchemaVersion   string `json:"s3SchemaVersion"`
		ConfigurationID string `json:"configurationId,omitempty"`
		Bucket          Bucket `json:"bucket"`
		Object          Object `json:"object"`
	}

	Bucket struct {
		Name          string       `json:"name"`
		OwnerIdentity UserIdentity `json:"ownerIdentity,omitempty"`
		Arn           string       `json:"arn,omitempty"`
	}

	Object struct {
		Key       string `json:"key"`
		Size      int64  `json:"size,omitempty"`
		VersionID string `json:"versionId,omitempty"`
		ETag      string `json:"eTag,omitempty"`
		Sequencer string `json:"sequencer,omitempty"`
	}
)

func (c *Controller) SendTestEvent(event *TestEvent, topic string) error {
	event.Time = time.Now()

	msg, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("couldn't marshal test event: %w", err)
	}

	return c.publish(topic, msg)
}

func (c *Controller) SendEvent(e *Event, id string, topic string) error {
	e.Records[0].S3.ConfigurationID = id

	msg, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("couldn't marshal %s event: %w", topic, err)
	}

	return c.publish(topic, msg)
}

func (c *Controller) publish(topic string, msg []byte) error {
	if _, err := c.jsClient.Publish(topic, msg); err != nil {
		return fmt.Errorf("couldn't send  event: %w", err)
	}

	return nil
}
