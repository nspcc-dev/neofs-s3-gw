package data

import (
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/notifications"
	"github.com/stretchr/testify/require"
)

func TestFilterTopics(t *testing.T) {
	config := NotificationConfiguration{
		QueueConfigurations: []QueueConfiguration{
			{
				ID:       "test1",
				QueueArn: "test1",
				Events:   []string{notifications.EventObjectCreated, notifications.EventObjectRemovedDelete},
			},
			{
				ID:       "test2",
				QueueArn: "test2",
				Events:   []string{notifications.EventObjectTagging},
				Filter: Filter{Key: Key{FilterRules: []FilterRule{
					{Name: "prefix", Value: "dir/"},
					{Name: "suffix", Value: ".png"},
				}}},
			},
		},
	}

	t.Run("no topics because suitable events not found", func(t *testing.T) {
		topics := config.FilterTopics(notifications.EventObjectACLPut, "dir/a.png")
		require.Empty(t, topics)
	})

	t.Run("no topics because of not suitable prefix", func(t *testing.T) {
		topics := config.FilterTopics(notifications.EventObjectTaggingPut, "dirw/cat.png")
		require.Empty(t, topics)
	})

	t.Run("no topics because of not suitable suffix", func(t *testing.T) {
		topics := config.FilterTopics(notifications.EventObjectTaggingPut, "a.jpg")
		require.Empty(t, topics)
	})

	t.Run("filter topics from queue configs without prefix suffix filter and exact event", func(t *testing.T) {
		topics := config.FilterTopics(notifications.EventObjectCreatedPut, "dir/a.png")
		require.Contains(t, topics, "test1")
		require.Len(t, topics, 1)
		require.Equal(t, topics["test1"], "test1")
	})

	t.Run("filter topics from queue configs with prefix suffix filter and '*' ending event", func(t *testing.T) {
		topics := config.FilterTopics(notifications.EventObjectTaggingPut, "dir/a.png")
		require.Contains(t, topics, "test2")
		require.Len(t, topics, 1)
		require.Equal(t, topics["test2"], "test2")
	})
}
