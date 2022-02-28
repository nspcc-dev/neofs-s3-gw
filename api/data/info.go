package data

import (
	"encoding/xml"
	"time"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
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
		CID                *cid.ID
		Owner              *owner.ID
		Created            time.Time
		BasicACL           uint32
		LocationConstraint string
		ObjectLockEnabled  bool
	}

	// ObjectInfo holds S3 object data.
	ObjectInfo struct {
		ID    *oid.ID
		CID   *cid.ID
		IsDir bool

		Bucket        string
		Name          string
		Size          int64
		ContentType   string
		Created       time.Time
		CreationEpoch uint64
		HashSum       string
		Owner         *owner.ID
		Headers       map[string]string
	}

	// BucketSettings stores settings such as versioning.
	BucketSettings struct {
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

// SettingsObjectName is system name for bucket settings file.
func (b *BucketInfo) SettingsObjectName() string { return bktSettingsObject }

// CORSObjectName returns system name for bucket CORS configuration file.
func (b *BucketInfo) CORSObjectName() string { return bktCORSConfigurationObject }

func (b *BucketInfo) NotificationConfigurationObjectName() string {
	return bktNotificationConfigurationObject
}

// Version returns object version from ObjectInfo.
func (o *ObjectInfo) Version() string { return o.ID.String() }

// NullableVersion returns object version from ObjectInfo.
// Return "null" if "S3-Versions-unversioned" header present.
func (o *ObjectInfo) NullableVersion() string {
	if _, ok := o.Headers["S3-Versions-unversioned"]; ok {
		return "null"
	}
	return o.Version()
}

// NiceName returns object name for cache.
func (o *ObjectInfo) NiceName() string { return o.Bucket + "/" + o.Name }

// Address returns object address.
func (o *ObjectInfo) Address() *address.Address {
	addr := address.NewAddress()
	addr.SetContainerID(o.CID)
	addr.SetObjectID(o.ID)

	return addr
}

// TagsObject returns name of system object for tags.
func (o *ObjectInfo) TagsObject() string { return ".tagset." + o.Name + "." + o.Version() }
