package api

// Standard S3 HTTP request/response constants.
const (
	MetadataPrefix       = "X-Amz-Meta-"
	AmzMetadataDirective = "X-Amz-Metadata-Directive"

	LastModified       = "Last-Modified"
	Date               = "Date"
	ETag               = "ETag"
	ContentType        = "Content-Type"
	ContentMD5         = "Content-Md5"
	ContentEncoding    = "Content-Encoding"
	Expires            = "Expires"
	ContentLength      = "Content-Length"
	ContentLanguage    = "Content-Language"
	ContentRange       = "Content-Range"
	Connection         = "Connection"
	AcceptRanges       = "Accept-Ranges"
	AmzBucketRegion    = "X-Amz-Bucket-Region"
	ServerInfo         = "Server"
	RetryAfter         = "Retry-After"
	Location           = "Location"
	CacheControl       = "Cache-Control"
	ContentDisposition = "Content-Disposition"
	Authorization      = "Authorization"
	Action             = "Action"
	IfModifiedSince    = "If-Modified-Since"
	IfUnmodifiedSince  = "If-Unmodified-Since"
	IfMatch            = "If-Match"
	IfNoneMatch        = "If-None-Match"

	AmzCopyIfModifiedSince   = "X-Amz-Copy-Source-If-Modified-Since"
	AmzCopyIfUnmodifiedSince = "X-Amz-Copy-Source-If-Unmodified-Since"
	AmzCopyIfMatch           = "X-Amz-Copy-Source-If-Match"
	AmzCopyIfNoneMatch       = "X-Amz-Copy-Source-If-None-Match"
)
