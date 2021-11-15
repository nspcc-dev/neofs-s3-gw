package data

import (
	"encoding/xml"
	"time"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
)

const (
	bktVersionSettingsObject   = ".s3-versioning-settings"
	bktCORSConfigurationObject = ".s3-cors"
)

type (
	// BucketInfo stores basic bucket data.
	BucketInfo struct {
		Name     string
		CID      *cid.ID
		Owner    *owner.ID
		Created  time.Time
		BasicACL uint32
	}

	// ObjectInfo holds S3 object data.
	ObjectInfo struct {
		ID    *object.ID
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
func (b *BucketInfo) SettingsObjectName() string { return bktVersionSettingsObject }

// CORSObjectName returns system name for bucket CORS configuration file.
func (b *BucketInfo) CORSObjectName() string { return bktCORSConfigurationObject }

// Version returns object version from ObjectInfo.
func (o *ObjectInfo) Version() string { return o.ID.String() }

// NiceName returns object name for cache.
func (o *ObjectInfo) NiceName() string { return o.Bucket + "/" + o.Name }

// Address returns object address.
func (o *ObjectInfo) Address() *object.Address {
	address := object.NewAddress()
	address.SetContainerID(o.CID)
	address.SetObjectID(o.ID)

	return address
}

// TagsObject returns name of system object for tags.
func (o *ObjectInfo) TagsObject() string { return ".tagset." + o.Name + "." + o.Version() }
