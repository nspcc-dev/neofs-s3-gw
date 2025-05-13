package s3headers

const (
	attributePrefix = "S3-"
)

const (
	multipartPrefix = attributePrefix + "MP-"

	// MultipartElementID is number of manual sliced part element.
	// Result: S3-MP-ElementId.
	MultipartElementID = multipartPrefix + "ElementId"
	// MultipartIsArbitraryPart describes multipart which has been uploaded in not the subsequent order.
	MultipartIsArbitraryPart = multipartPrefix + "IsArbitrary"
	// MultipartTotalSize describes payload size for all manually sliced elements for part.
	// Size of the last element in chain is a whole part size.
	MultipartTotalSize = multipartPrefix + "TotalSize"

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
	// MultipartHomoHash contains hash.Hash state to calculate final object homo hash.
	MultipartHomoHash = multipartPrefix + "HomoHash"
	// MultipartPartHash contains hash for MultipartPartNumber.
	MultipartPartHash = multipartPrefix + "PartHash"
	// MultipartOwner contains object owner for uploading object.
	MultipartOwner = multipartPrefix + "Owner"
	// MultipartCopiesNumber contains CopiesNumber setting for uploading object.
	MultipartCopiesNumber = multipartPrefix + "CopiesNumber"
	// MultipartMeta contains original object attributes.
	MultipartMeta = multipartPrefix + "Meta"
	// MultipartCreated contains final object creation date.
	MultipartCreated = multipartPrefix + "Created"
)

const (
	// MetaType is a header name to identify meta containers for objects.
	// Result: S3-MetaType.
	MetaType = attributePrefix + "MetaType"

	TypeLock              = "lock"
	TypeTags              = "tags"
	TypeBucketTags        = "bucketTags"
	TypeBucketNotifConfig = "bucketNotifConf"
	TypeBucketCORS        = "bucketCORS"
	TypeBucketSettings    = "bucketSettings"
	TypeMultipartInfo     = "multipartInfo"
	TypeMultipartPart     = "multipartPart"
)

const (
	bucketSettingsPrefix = attributePrefix + "BucketSettings-"

	// BucketSettingsVersioning contains versioning setting for bucket.
	BucketSettingsVersioning = bucketSettingsPrefix + "Versioning"
	// BucketSettingsMetaVersion contains version of bucket settings file.
	BucketSettingsMetaVersion = bucketSettingsPrefix + "MetaVersion"

	AttributeObjectVersion = attributePrefix + "ObjectVersion"
	AttributeObjectNonce   = "__NEOFS__NONCE"

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
	UploadCompletedParts         = NeoFSSystemMetadataPrefix + "Completed-Parts"

	// Result: S3-Meta-Tag-.
	NeoFSSystemMetadataTagPrefix = NeoFSSystemMetadataPrefix + "Tag-"
)

const (
	FieldComplianceMode     = "ComplianceMode"
	FieldRetentionUntilMode = "RetentionUntil"
)
