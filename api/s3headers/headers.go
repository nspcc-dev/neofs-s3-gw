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

	// Result: S3-Encryption-Meta.
	AttributeEncryptionMeta = attributePrefix + "Encryption-Meta"

	NeoFSSystemMetadataPrefix = attributePrefix + "Meta-"
	AttributeVersioningState  = NeoFSSystemMetadataPrefix + "VersioningState"
	AttributeDeleteMarker     = NeoFSSystemMetadataPrefix + "DeleteMarker"

	// Result: S3-Meta-Tag-.
	NeoFSSystemMetadataTagPrefix = NeoFSSystemMetadataPrefix + "Tag-"
)

const (
	FieldComplianceMode     = "ComplianceMode"
	FieldRetentionUntilMode = "RetentionUntil"
)

// emptyTagValue is stored in NeoFS attribute instead of an empty tag value,
// since NeoFS rejects empty attribute values. S3 tag values can't contain "*".
const emptyTagValue = "*"

// EncodeTagValue returns tag value to be stored in NeoFS attribute.
func EncodeTagValue(v string) string {
	if v == "" {
		return emptyTagValue
	}

	return v
}

// DecodeTagValue returns tag value from NeoFS attribute value.
func DecodeTagValue(v string) string {
	if v == emptyTagValue {
		return ""
	}

	return v
}
