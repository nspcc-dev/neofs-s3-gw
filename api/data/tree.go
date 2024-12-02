package data

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

const (
	UnversionedObjectVersionID = "null"
)

// NodeVersion represent node from tree service.
type NodeVersion struct {
	BaseNodeVersion
	DeleteMarker  *DeleteMarkerInfo
	IsUnversioned bool
}

func (v NodeVersion) IsDeleteMarker() bool {
	return v.DeleteMarker != nil
}

// DeleteMarkerInfo is used to save object info if node in the tree service is delete marker.
// We need this information because the "delete marker" object is no longer stored in NeoFS.
type DeleteMarkerInfo struct {
	Created time.Time
	Owner   user.ID
}

// ExtendedObjectInfo contains additional node info to be able to sort versions by timestamp.
type ExtendedObjectInfo struct {
	ObjectInfo  *ObjectInfo
	NodeVersion *NodeVersion
	IsLatest    bool
}

func (e ExtendedObjectInfo) Version() string {
	if e.NodeVersion.IsUnversioned {
		return UnversionedObjectVersionID
	}

	return e.ObjectInfo.ID.EncodeToString()
}

// BaseNodeVersion is minimal node info from tree service.
// Basically used for "system" object.
type BaseNodeVersion struct {
	ID        uint64
	ParenID   uint64
	OID       oid.ID
	Timestamp uint64
	Size      int64
	ETag      string
	FilePath  string
}

type ObjectTaggingInfo struct {
	CnrID     cid.ID
	ObjName   string
	VersionID string
}

// MultipartInfo is multipart upload information.
type MultipartInfo struct {
	// ID is node id in tree service.
	// It's ignored when creating a new multipart upload.
	ID           uint64
	Key          string
	UploadID     string
	Owner        user.ID
	OwnerPubKey  keys.PublicKey
	Created      time.Time
	Meta         map[string]string
	CopiesNumber uint32
}

// LinkObjectPayload contains part info of the complex object.
// This data will be used for linking object construction.
type LinkObjectPayload struct {
	OID  oid.ID
	Size uint32
}

// Marshal converts LinkObjectPayload to string.
func (e *LinkObjectPayload) Marshal() string {
	return fmt.Sprintf("%s:%d", e.OID.String(), e.Size)
}

// Unmarshal converts string to LinkObjectPayload.
func (e *LinkObjectPayload) Unmarshal(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid format: %s", value)
	}

	if err := e.OID.DecodeString(parts[0]); err != nil {
		return fmt.Errorf("invalid id: %w", err)
	}

	size, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid size: %w", err)
	}

	e.Size = uint32(size)
	return nil
}

// PartInfo is upload information about part.
type PartInfo struct {
	Key      string
	UploadID string
	Number   int
	OID      oid.ID
	Size     int64
	ETag     string
	// Creation time from the client.
	Created time.Time
	// Server creation time.
	ServerCreated time.Time

	// MultipartHash contains internal state of the [hash.Hash] to calculate whole object payload hash.
	MultipartHash []byte
	// HomoHash contains internal state of the [hash.Hash] to calculate whole object homomorphic payload hash.
	HomoHash []byte
	// Elements contain [oid.ID] and size for each element for the current part.
	Elements []LinkObjectPayload
}

// ToHeaderString form short part representation to use in S3-Completed-Parts header.
func (p *PartInfo) ToHeaderString() string {
	return strconv.Itoa(p.Number) + "-" + strconv.FormatInt(p.Size, 10) + "-" + p.ETag
}

// SortPartInfo sorts PartInfo for Number ASC, ServerCreated ASC.
func SortPartInfo(a, b *PartInfo) int {
	if a.Number < b.Number {
		return -1
	}

	if a.Number == b.Number {
		if a.ServerCreated.Before(b.ServerCreated) {
			return -1
		}

		if a.ServerCreated.Equal(b.ServerCreated) {
			return 0
		}
	}

	return 1
}

// LockInfo is lock information to create appropriate tree node.
type LockInfo struct {
	id uint64

	legalHoldOID oid.ID
	setLegalHold bool

	retentionOID oid.ID
	setRetention bool
	untilDate    string
	isCompliance bool
}

func NewLockInfo(id uint64) *LockInfo {
	return &LockInfo{id: id}
}

func (l LockInfo) ID() uint64 {
	return l.id
}

func (l *LockInfo) SetLegalHold(objID oid.ID) {
	l.legalHoldOID = objID
	l.setLegalHold = true
}

func (l *LockInfo) ResetLegalHold() {
	l.setLegalHold = false
}

func (l LockInfo) LegalHold() oid.ID {
	return l.legalHoldOID
}

func (l LockInfo) IsLegalHoldSet() bool {
	return l.setLegalHold
}

func (l *LockInfo) SetRetention(objID oid.ID, until string, isCompliance bool) {
	l.retentionOID = objID
	l.setRetention = true
	l.untilDate = until
	l.isCompliance = isCompliance
}

func (l LockInfo) IsRetentionSet() bool {
	return l.setRetention
}

func (l LockInfo) Retention() oid.ID {
	return l.retentionOID
}

func (l LockInfo) UntilDate() string {
	return l.untilDate
}

func (l LockInfo) IsCompliance() bool {
	return l.isCompliance
}
