package s3headers

import (
	"sort"
	"strings"

	"github.com/nspcc-dev/neofs-sdk-go/object"
)

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
	AttributeEmptyMetaKeys    = NeoFSSystemMetadataPrefix + "EmptyMetaKeys"

	// Result: S3-Meta-Tag-.
	NeoFSSystemMetadataTagPrefix = NeoFSSystemMetadataPrefix + "Tag-"
)

const (
	FieldComplianceMode     = "ComplianceMode"
	FieldRetentionUntilMode = "RetentionUntil"
)

// GetStoredHeaders returns headers with the empty values moved into AttributeEmptyMetaKeys.
func GetStoredHeaders(headers map[string]string) map[string]string {
	var (
		empty  []string
		stored = make(map[string]string, len(headers)+1)
	)

	for k, v := range headers {
		if v == "" {
			empty = append(empty, k)
		} else {
			stored[k] = v
		}
	}

	if len(empty) > 0 {
		sort.Strings(empty)
		stored[AttributeEmptyMetaKeys] = strings.Join(empty, ",")
	}

	return stored
}

// GetMetaAttributes process headeers and returns NeoFS attributes for an object.
func GetMetaAttributes(headers map[string]string) []object.Attribute {
	var (
		empty []string
		attrs = make([]object.Attribute, 0, len(headers)+1)
	)

	for k, v := range headers {
		if v == "" {
			empty = append(empty, k)
		} else {
			attrs = append(attrs, object.NewAttribute(k, v))
		}
	}

	if len(empty) > 0 {
		sort.Strings(empty)
		attrs = append(attrs, object.NewAttribute(AttributeEmptyMetaKeys, strings.Join(empty, ",")))
	}

	return attrs
}

// RestoreEmptyHeaders is the inverse of GetStoredHeaders, in place.
func RestoreEmptyHeaders(headers map[string]string) {
	list, ok := headers[AttributeEmptyMetaKeys]
	if !ok {
		return
	}

	delete(headers, AttributeEmptyMetaKeys)
	for k := range strings.SplitSeq(list, ",") {
		if k != "" {
			headers[k] = ""
		}
	}
}

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
