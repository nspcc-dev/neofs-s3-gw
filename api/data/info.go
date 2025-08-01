package data

import (
	"encoding/xml"
	"time"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

const (
	bktSettingsObject                  = ".s3-settings"
	bktCORSConfigurationObject         = ".s3-cors"
	bktNotificationConfigurationObject = ".s3-notifications"

	VersioningUnversioned = "Unversioned"
	VersioningEnabled     = "Enabled"
	VersioningSuspended   = "Suspended"

	// BucketSettingsV1 describes v1 version identifier for the bucket settings file.
	BucketSettingsV1 = "1"
)

const (
	// BucketOwnerEnforced is a enforced state.
	BucketOwnerEnforced = iota
	// BucketOwnerPreferred is a preferred state.
	BucketOwnerPreferred
	// BucketOwnerPreferredAndRestricted is a preferred state with `bucket-owner-full-control` restriction applied.
	BucketOwnerPreferredAndRestricted
	// BucketOwnerObjectWriter is a object writer state.
	BucketOwnerObjectWriter
)

type (
	// BucketOwner is bucket onwer state.
	BucketOwner int

	// BucketACLState is bucket ACL state.
	BucketACLState uint32

	// BucketInfo stores basic bucket data.
	BucketInfo struct {
		Name               string
		CID                cid.ID
		Owner              user.ID
		Created            time.Time
		LocationConstraint string
		ObjectLockEnabled  bool
	}

	// ObjectInfo holds S3 object data.
	ObjectInfo struct {
		ID             oid.ID
		CID            cid.ID
		IsDir          bool
		IsDeleteMarker bool

		Bucket      string
		Name        string
		Size        int64
		ContentType string
		Created     time.Time
		HashSum     string
		Owner       user.ID
		Headers     map[string]string
		Version     string
	}

	// ObjectListResponseContent holds response data for object listing.
	ObjectListResponseContent struct {
		ID      oid.ID
		IsDir   bool
		Size    int64
		Owner   user.ID
		HashSum string
		Created time.Time
		Name    string
	}

	// NotificationInfo store info to send s3 notification.
	NotificationInfo struct {
		Name    string
		Version string
		Size    int64
		HashSum string
	}

	// BucketSettings stores settings such as versioning.
	BucketSettings struct {
		Versioning        string                   `json:"versioning"`
		LockConfiguration *ObjectLockConfiguration `json:"lock_configuration"`
		BucketOwner       BucketOwner              `json:"bucket_owner"`
	}

	// CORSConfiguration stores CORS configuration of a request.
	CORSConfiguration struct {
		XMLName   xml.Name   `xml:"CORSConfiguration" json:"-"`
		CORSRules []CORSRule `xml:"CORSRule" json:"CORSRules"`
	}

	// CORSRule stores rules for CORS in a bucket.
	CORSRule struct {
		ID             string   `xml:"ID,omitempty" json:"ID,omitempty"`
		AllowedHeaders []string `xml:"AllowedHeader" json:"AllowedHeaders"`
		AllowedMethods []string `xml:"AllowedMethod" json:"AllowedMethods"`
		AllowedOrigins []string `xml:"AllowedOrigin" json:"AllowedOrigins"`
		ExposeHeaders  []string `xml:"ExposeHeader" json:"ExposeHeaders"`
		MaxAgeSeconds  int      `xml:"MaxAgeSeconds,omitempty" json:"MaxAgeSeconds,omitempty"`
	}
)

// NotificationInfoFromObject creates new NotificationInfo from ObjectInfo.
func NotificationInfoFromObject(objInfo *ObjectInfo) *NotificationInfo {
	return &NotificationInfo{
		Name:    objInfo.Name,
		Version: objInfo.VersionID(),
		Size:    objInfo.Size,
		HashSum: objInfo.HashSum,
	}
}

// SettingsObjectName is a system name for a bucket settings file.
func (b *BucketInfo) SettingsObjectName() string { return bktSettingsObject }

// CORSObjectName returns a system name for a bucket CORS configuration file.
func (b *BucketInfo) CORSObjectName() string { return bktCORSConfigurationObject }

func (b *BucketInfo) NotificationConfigurationObjectName() string {
	return bktNotificationConfigurationObject
}

// VersionID returns object version from ObjectInfo.
func (o *ObjectInfo) VersionID() string { return o.ID.EncodeToString() }

// NiceName returns object name for cache.
func (o *ObjectInfo) NiceName() string { return o.Bucket + "/" + o.Name }

// Address returns object address.
func (o *ObjectInfo) Address() oid.Address {
	return oid.NewAddress(o.CID, o.ID)
}

func (b BucketSettings) Unversioned() bool {
	return b.Versioning == VersioningUnversioned
}

func (b BucketSettings) VersioningEnabled() bool {
	return b.Versioning == VersioningEnabled
}

func (b BucketSettings) VersioningSuspended() bool {
	return b.Versioning == VersioningSuspended
}
