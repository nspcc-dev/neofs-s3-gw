package notifications

import (
	"encoding/json"
	"fmt"
	"time"
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
)

func (c *Controller) SendTestEvent(event *TestEvent, topic string) error {
	event.Time = time.Now()

	msg, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("couldn't marshal test event: %w", err)
	}

	return c.publish(topic, msg)
}

func (c *Controller) publish(topic string, msg []byte) error {
	if _, err := c.jsClient.Publish(topic, msg); err != nil {
		return fmt.Errorf("couldn't send  event: %w", err)
	}

	return nil
}
