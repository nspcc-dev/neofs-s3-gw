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
)

type (
	// BucketInfo stores basic bucket data.
	BucketInfo struct {
		Name               string
		CID                cid.ID
		Owner              user.ID
		Created            time.Time
		BasicACL           uint32
		LocationConstraint string
		ObjectLockEnabled  bool
	}

	// ObjectInfo holds S3 object data.
	ObjectInfo struct {
		ID    oid.ID
		CID   cid.ID
		IsDir bool

		Bucket        string
		Name          string
		Size          int64
		ContentType   string
		Created       time.Time
		CreationEpoch uint64
		HashSum       string
		Owner         user.ID
		Headers       map[string]string
	}

	// BucketSettings stores settings such as versioning.
	BucketSettings struct {
		IsNoneStatus      bool
		VersioningEnabled bool                     `json:"versioning_enabled"`
		LockConfiguration *ObjectLockConfiguration `json:"lock_configuration"`
	}

	// CORSConfiguration stores CORS configuration of a request.
	CORSConfiguration struct {
		XMLName   xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CORSConfiguration" json:"-"`
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

// SettingsObjectName is a system name for a bucket settings file.
func (b *BucketInfo) SettingsObjectName() string { return bktSettingsObject }

// CORSObjectName returns a system name for a bucket CORS configuration file.
func (b *BucketInfo) CORSObjectName() string { return bktCORSConfigurationObject }

func (b *BucketInfo) NotificationConfigurationObjectName() string {
	return bktNotificationConfigurationObject
}

// Version returns object version from ObjectInfo.
func (o *ObjectInfo) Version() string { return o.ID.EncodeToString() }

// NullableVersion returns object version from ObjectInfo.
// Return "null" if "S3-Versions-unversioned" header is present.
func (o *ObjectInfo) NullableVersion() string {
	if _, ok := o.Headers["S3-Versions-unversioned"]; ok {
		return "null"
	}
	return o.Version()
}

// NiceName returns object name for cache.
func (o *ObjectInfo) NiceName() string { return o.Bucket + "/" + o.Name }

// Address returns object address.
func (o *ObjectInfo) Address() oid.Address {
	var addr oid.Address
	addr.SetContainer(o.CID)
	addr.SetObject(o.ID)

	return addr
}

// TagsObject returns the name of a system object for tags.
func (o *ObjectInfo) TagsObject() string { return ".tagset." + o.Name + "." + o.Version() }

// LegalHoldObject returns the name of a system object for a lock object.
func (o *ObjectInfo) LegalHoldObject() string { return ".lock." + o.Name + "." + o.Version() }

// RetentionObject returns the name of a system object for a retention lock object.
func (o *ObjectInfo) RetentionObject() string { return ".retention." + o.Name + "." + o.Version() }
