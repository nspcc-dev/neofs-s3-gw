package api

import (
	"time"

	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
)

const bktVersionSettingsObject = ".s3-versioning-settings"

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
)

// SettingsObjectName is system name for bucket settings file.
func (b *BucketInfo) SettingsObjectName() string { return bktVersionSettingsObject }

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
