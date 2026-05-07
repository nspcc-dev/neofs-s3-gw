package s3headers

const (
	attributePrefix = "S3-"
)

const (
	multipartPrefix = attributePrefix + "MP-"

	// MultipartObjectKey contains object key for multipart object.
	// It is important to store it separately with object.AttributeFilePath attribute during multipart upload.
	// Multipart uploading object shouldn't be available for user until CompleteMultipartUpload.
	MultipartObjectKey = multipartPrefix + "ObjectKey"

	// MultipartUpload contains multipart upload ID.
	MultipartUpload = multipartPrefix + "Upload"
	// MultipartPartNumber contains part number in MultipartUpload.
	MultipartPartNumber = multipartPrefix + "PartNumber"
	// MultipartHash contains hash.Hash state to calculate final object hash.
	MultipartHash = multipartPrefix + "Hash"
	// MultipartMeta contains original object attributes.
	MultipartMeta = multipartPrefix + "Meta"
	// MultipartCreated contains final object creation date.
	MultipartCreated = multipartPrefix + "Created"
)

const (
	// MetaType is a header name to identify meta containers for objects.
	// Result: S3-MetaType.
	MetaType = attributePrefix + "MetaType"

	TypeTags          = "tags"
	TypeMultipartInfo = "multipartInfo"
	TypeMultipartPart = "multipartPart"
)

const (
	AttributeObjectNonce = "__NEOFS__NONCE"

	// Result: S3-Lock-Meta.
	AttributeLockMeta = attributePrefix + "Lock-Meta"

	NeoFSSystemMetadataPrefix = attributePrefix + "Meta-"
	// Result: S3-Meta-Algorithm.
	AttributeEncryptionAlgorithm = NeoFSSystemMetadataPrefix + "Algorithm"
	AttributeDecryptedSize       = NeoFSSystemMetadataPrefix + "Decrypted-Size"
	AttributeHMACSalt            = NeoFSSystemMetadataPrefix + "HMAC-Salt"
	AttributeHMACKey             = NeoFSSystemMetadataPrefix + "HMAC-Key"
	AttributeVersioningState     = NeoFSSystemMetadataPrefix + "VersioningState"
	AttributeDeleteMarker        = NeoFSSystemMetadataPrefix + "DeleteMarker"

	// Result: S3-Meta-Tag-.
	NeoFSSystemMetadataTagPrefix = NeoFSSystemMetadataPrefix + "Tag-"
)

const (
	FieldComplianceMode     = "ComplianceMode"
	FieldRetentionUntilMode = "RetentionUntil"
)
