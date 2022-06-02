package data

import (
	"strconv"
	"time"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// NodeVersion represent node from tree service.
type NodeVersion struct {
	BaseNodeVersion
	DeleteMarker  *DeleteMarkerInfo
	IsUnversioned bool
}

// DeleteMarkerInfo is used to save object info if node in the tree service is delete marker.
// We need this information because the "delete marker" object is no longer stored in NeoFS.
type DeleteMarkerInfo struct {
	FilePath string
	Created  time.Time
	Owner    user.ID
}

// ExtendedObjectInfo contains additional node info to be able to sort versions by timestamp.
type ExtendedObjectInfo struct {
	ObjectInfo  *ObjectInfo
	NodeVersion *NodeVersion
	IsLatest    bool
}

// BaseNodeVersion is minimal node info from tree service.
// Basically used for "system" object.
type BaseNodeVersion struct {
	ID        uint64
	OID       oid.ID
	Timestamp uint64
}

type ObjectTaggingInfo struct {
	CnrID     *cid.ID
	ObjName   string
	VersionID string
}

// MultipartInfo is multipart upload information.
type MultipartInfo struct {
	// ID is node id in tree service.
	// It's ignored when creating a new multipart upload.
	ID       uint64
	Key      string
	UploadID string
	Owner    user.ID
	Created  time.Time
	Meta     map[string]string
}

// PartInfo is upload information about part.
type PartInfo struct {
	Key      string
	UploadID string
	Number   int
	OID      oid.ID
	Size     int64
	ETag     string
	Created  time.Time
}

// ToHeaderString form short part representation to use in S3-Completed-Parts header.
func (p *PartInfo) ToHeaderString() string {
	return strconv.Itoa(p.Number) + "-" + strconv.FormatInt(p.Size, 10) + "-" + p.ETag
}

// LockInfo is lock information to create appropriate tree node.
type LockInfo struct {
	ID           uint64
	LegalHoldOID *oid.ID
	RetentionOID *oid.ID
	UntilDate    string
	IsCompliance bool
}
