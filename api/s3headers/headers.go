package s3headers

const (
	// MultipartElementID is number of manual sliced part element.
	MultipartElementID = "s3mpElementId"
	// MultipartIsArbitraryPart describes multipart which has been uploaded in not the subsequent order.
	MultipartIsArbitraryPart = "s3mpIsArbitrary"
	// MultipartTotalSize describes payload size for all manually sliced elements for part.
	// Size of the last element in chain is a whole part size.
	MultipartTotalSize = "s3mpTotalSize"

	// MultipartObjectKey contains object key for multipart object.
	// It is important to store it separately with object.AttributeFilePath attribute during multipart upload.
	// Multipart uploading object shouldn't be available for user until CompleteMultipartUpload.
	MultipartObjectKey = "s3mpObjectKey"

	// MultipartUpload contains multipart upload ID.
	MultipartUpload = "s3mpUpload"
	// MultipartPartNumber contains part number in MultipartUpload.
	MultipartPartNumber = "s3mpPartNumber"
	// MultipartHash contains hash.Hash state to calculate final object hash.
	MultipartHash = "s3mpHash"
	// MultipartHomoHash contains hash.Hash state to calculate final object homo hash.
	MultipartHomoHash = "s3mpHomoHash"
	// MultipartPartHash contains hash for MultipartPartNumber.
	MultipartPartHash = "s3mpPartHash"
	// MultipartOwner contains object owner for uploading object.
	MultipartOwner = "s3mpOwner"
	// MultipartCopiesNumber contains CopiesNumber setting for uploading object.
	MultipartCopiesNumber = "s3mpCopiesNumber"
	// MultipartMeta contains original object attributes.
	MultipartMeta = "s3mpMeta"
	// MultipartCreated contains final object creation date.
	MultipartCreated = "s3mpCreated"
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
