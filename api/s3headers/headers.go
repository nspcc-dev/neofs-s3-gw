package s3headers

const (
	ElementID   = "elementId"
	IsArbitrary = "isArbitrary"
	TotalSize   = "totalSize"

	ObjectKey = "mpObjectKey"
)

const (
	// MetaType is a header name to identify meta containers for objects.
	MetaType = "s3MetaType"

	TypeLock = "lock"
	TypeTags = "tags"
)

const (
	// MetaMultipartType is a header name to identify multipart meta for objects.
	MetaMultipartType = "s3MetaMultipartType"

	TypeMultipartInfo = "info"
	TypeMultipartPart = "part"
)
