package api

import (
	"github.com/pkg/errors"
)

// errInvalidArgument means that input argument is invalid.
var errInvalidArgument = errors.New("Invalid arguments specified")

// errMethodNotAllowed means that method is not allowed.
var errMethodNotAllowed = errors.New("Method not allowed")

// errSignatureMismatch means signature did not match.
var errSignatureMismatch = errors.New("Signature does not match")

// used when we deal with data larger than expected
var errSizeUnexpected = errors.New("Data size larger than expected")

// used when we deal with data with unknown size
var errSizeUnspecified = errors.New("Data size is unspecified")

// When upload object size is greater than 5G in a single PUT/POST operation.
var errDataTooLarge = errors.New("Object size larger than allowed limit")

// When upload object size is less than what was expected.
var errDataTooSmall = errors.New("Object size smaller than expected")

// errServerNotInitialized - server not initialized.
var errServerNotInitialized = errors.New("Server not initialized, please try again")

// errRPCAPIVersionUnsupported - unsupported rpc API version.
var errRPCAPIVersionUnsupported = errors.New("Unsupported rpc API version")

// errServerTimeMismatch - server times are too far apart.
var errServerTimeMismatch = errors.New("Server times are too far apart")

// errInvalidBucketName - bucket name is reserved for MinIO, usually
// returned for 'minio', '.minio.sys', buckets with capital letters.
var errInvalidBucketName = errors.New("The specified bucket is not valid")

// errInvalidRange - returned when given range value is not valid.
var errInvalidRange = errors.New("Invalid range")

// errInvalidRangeSource - returned when given range value exceeds
// the source object size.
var errInvalidRangeSource = errors.New("Range specified exceeds source object size")

// error returned by disks which are to be initialized are waiting for the
// first server to initialize them in distributed set to initialize them.
var errNotFirstDisk = errors.New("Not first disk")

// error returned by first disk waiting to initialize other servers.
var errFirstDiskWait = errors.New("Waiting on other disks")

// error returned when a bucket already exists
var errBucketAlreadyExists = errors.New("Your previous request to create the named bucket succeeded and you already own it")

// error returned for a negative actual size.
var errInvalidDecompressedSize = errors.New("Invalid Decompressed Size")

// error returned in IAM subsystem when user doesn't exist.
var errNoSuchUser = errors.New("Specified user does not exist")

// error returned in IAM subsystem when groups doesn't exist.
var errNoSuchGroup = errors.New("Specified group does not exist")

// error returned in IAM subsystem when a non-empty group needs to be
// deleted.
var errGroupNotEmpty = errors.New("Specified group is not empty - cannot remove it")

// error returned in IAM subsystem when policy doesn't exist.
var errNoSuchPolicy = errors.New("Specified canned policy does not exist")

// error returned in IAM subsystem when an external users systems is configured.
var errIAMActionNotAllowed = errors.New("Specified IAM action is not allowed with LDAP configuration")

// error returned in IAM subsystem when IAM sub-system is still being initialized.
var errIAMNotInitialized = errors.New("IAM sub-system is being initialized, please try again")

// error returned when access is denied.
var errAccessDenied = errors.New("Do not have enough permissions to access this resource")

// error returned when object is locked.
var errLockedObject = errors.New("Object is WORM protected and cannot be overwritten or deleted")

var (
	errInvalidAccessKeyID   = errors.New("The access key ID you provided does not exist in our records")
	errChangeCredNotAllowed = errors.New("Changing access key and secret key not allowed")
	errAuthentication       = errors.New("Authentication failed, check your access credentials")
	errNoAuthToken          = errors.New("JWT token missing")
	errIncorrectCreds       = errors.New("Current access key or secret key is incorrect")
	errPresignedNotAllowed  = errors.New("Unable to generate shareable URL due to lack of read permissions")
)

var (
	// AWS errors for invalid SSE-C requests.
	errEncryptedObject      = errors.New("The object was stored using a form of SSE")
	errInvalidSSEParameters = errors.New("The SSE-C key for key-rotation is not correct") // special access denied
	errKMSNotConfigured     = errors.New("KMS not configured for a server side encrypted object")
	// Additional MinIO errors for SSE-C requests.
	errObjectTampered = errors.New("The requested object was modified and may be compromised")
	// error returned when invalid encryption parameters are specified
	errInvalidEncryptionParameters = errors.New("The encryption parameters are not applicable to this object")
)

// ErrNoEntriesFound - Indicates no entries were found for the given key (directory)
var ErrNoEntriesFound = errors.New("No entries found for this key")
