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

	// TopicConfiguration and LambdaFunctionConfiguration -- we don't support these configurations
	// but we need them to detect in notification configurations in requests.
	TopicConfiguration          struct{}
	LambdaFunctionConfiguration struct{}
)

var ValidEvents = map[string]struct{}{
	"s3:ReducedRedundancyLostObject":                   {},
	"s3:ObjectCreated:*":                               {},
	"s3:ObjectCreated:Put":                             {},
	"s3:ObjectCreated:Post":                            {},
	"s3:ObjectCreated:Copy":                            {},
	"s3:ObjectCreated:CompleteMultipartUpload":         {},
	"s3:ObjectRemoved:*":                               {},
	"s3:ObjectRemoved:Delete":                          {},
	"s3:ObjectRemoved:DeleteMarkerCreated":             {},
	"s3:ObjectRestore:*":                               {},
	"s3:ObjectRestore:Post":                            {},
	"s3:ObjectRestore:Completed":                       {},
	"s3:Replication:*":                                 {},
	"s3:Replication:OperationFailedReplication":        {},
	"s3:Replication:OperationNotTracked":               {},
	"s3:Replication:OperationMissedThreshold":          {},
	"s3:Replication:OperationReplicatedAfterThreshold": {},
	"s3:ObjectRestore:Delete":                          {},
	"s3:LifecycleTransition":                           {},
	"s3:IntelligentTiering":                            {},
	"s3:ObjectAcl:Put":                                 {},
	"s3:LifecycleExpiration:*":                         {},
	"s3:LifecycleExpiration:Delete":                    {},
	"s3:LifecycleExpiration:DeleteMarkerCreated":       {},
	"s3:ObjectTagging:*":                               {},
	"s3:ObjectTagging:Put":                             {},
	"s3:ObjectTagging:Delete":                          {},
}

func (n NotificationConfiguration) IsEmpty() bool {
	return len(n.QueueConfigurations) == 0 && len(n.TopicConfigurations) == 0 && len(n.LambdaFunctionConfigurations) == 0
}
