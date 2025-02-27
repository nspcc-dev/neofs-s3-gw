package s3headers

const (
	// MetaType is a header name to identify meta containers for objects.
	MetaType = "s3MetaType"

	TypeLock = "lock"
	TypeTags = "tags"
)
