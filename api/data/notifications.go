package data

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

	// TopicConfiguration and LambdaFunctionConfiguration -- we don't support these configurations,
	// but we need them to detect in notification configurations in requests.
	TopicConfiguration          struct{}
	LambdaFunctionConfiguration struct{}
)

func (n NotificationConfiguration) IsEmpty() bool {
	return len(n.QueueConfigurations) == 0 && len(n.TopicConfigurations) == 0 && len(n.LambdaFunctionConfigurations) == 0
}
