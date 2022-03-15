package data

import "strings"

type (
	NotificationConfiguration struct {
		QueueConfigurations []QueueConfiguration `xml:"QueueConfiguration" json:"QueueConfigurations"`
		// Not supported topics
		TopicConfigurations          []TopicConfiguration          `xml:"TopicConfiguration" json:"TopicConfigurations"`
		LambdaFunctionConfigurations []LambdaFunctionConfiguration `xml:"CloudFunctionConfiguration" json:"CloudFunctionConfigurations"`
	}

	QueueConfiguration struct {
		ID       string   `xml:"Id" json:"Id"`
		QueueArn string   `xml:"Queue" json:"Queue"`
		Events   []string `xml:"Event" json:"Events"`
		Filter   Filter   `xml:"Filter" json:"Filter"`
	}

	Filter struct {
		Key Key `xml:"S3Key" json:"S3Key"`
	}

	Key struct {
		FilterRules []FilterRule `xml:"FilterRule" json:"FilterRules"`
	}

	FilterRule struct {
		Name  string `xml:"Name" json:"Name"`
		Value string `xml:"Value" json:"Value"`
	}

	// TopicConfiguration and LambdaFunctionConfiguration -- we don't support these configurations
	// but we need them to detect in notification configurations in requests.
	TopicConfiguration          struct{}
	LambdaFunctionConfiguration struct{}
)

func (n NotificationConfiguration) IsEmpty() bool {
	return len(n.QueueConfigurations) == 0 && len(n.TopicConfigurations) == 0 && len(n.LambdaFunctionConfigurations) == 0
}

func (n NotificationConfiguration) FilterTopics(eventType, name string) map[string]string {
	topics := make(map[string]string)

	for _, t := range n.QueueConfigurations {
		event := false
		for _, e := range t.Events {
			// the second condition is comparison with events ending with *:
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
			if f.Name == "prefix" && !strings.HasPrefix(name, f.Value) {
				filter = false
				break
			} else if f.Name == "suffix" && !strings.HasSuffix(name, f.Value) {
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
