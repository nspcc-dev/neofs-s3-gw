package data

import (
	"cmp"
	"strconv"
	"strings"
	"time"

	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

const (
	UnversionedObjectVersionID = "null"
)

// NodeVersion represent basic object metadata.
type NodeVersion struct {
	OID            oid.ID
	Timestamp      uint64
	ETag           string
	FilePath       string
	IsDeleteMarker bool
	IsUnversioned  bool
}

// ExtendedObjectInfo contains additional node info to be able to sort versions by timestamp.
type ExtendedObjectInfo struct {
	ObjectInfo  *ObjectInfo
	NodeVersion *NodeVersion
	IsLatest    bool
}

// ComprehensiveObjectInfo represents metasearch result for object, with tags and lock data.
type ComprehensiveObjectInfo struct {
	ID       oid.ID
	TagSet   map[string]string
	LockInfo *LockInfo
}

func (e ExtendedObjectInfo) Version() string {
	if e.NodeVersion.IsUnversioned {
		return UnversionedObjectVersionID
	}

	return e.ObjectInfo.ID.EncodeToString()
}

// MultipartInfo is multipart upload information.
type MultipartInfo struct {
	ID       oid.ID
	Key      string
	UploadID string
	Owner    user.ID
	Created  time.Time
	Meta     map[string]string
}

// PartInfo is upload information about part.
type PartInfo struct {
	UploadID string
	Number   int
	OID      oid.ID
	Size     int64
	ETag     string
	// Creation time from the client.
	Created time.Time

	// MultipartHash contains internal state of the [hash.Hash] to calculate whole object payload hash.
	MultipartHash []byte
	// HomoHash contains internal state of the [hash.Hash] to calculate whole object homomorphic payload hash.
	HomoHash []byte
	// Elements contain [oid.ID] and size for each element for the current part.
	Elements []ElementInfo
}

// ElementInfo represents small element in "big object" chain.
type ElementInfo struct {
	ID         oid.ID
	ElementID  int
	Attributes map[string]string
	Size       int64
	TotalSize  int64
}

// ToHeaderString form short part representation to use in S3-Completed-Parts header.
func (p *PartInfo) ToHeaderString() string {
	return strings.Join([]string{
		strconv.Itoa(p.Number),
		strconv.FormatInt(p.Size, 10),
		p.ETag,
		p.OID.String(),
	}, "-")
}

// SortPartInfo sorts PartInfo for Number ASC, ServerCreated ASC.
func SortPartInfo(a, b *PartInfo) int {
	return cmp.Compare(a.Number, b.Number)
}

// LockInfo is lock information for a particular object.
type LockInfo struct {
	legalHoldOID oid.ID
	setLegalHold bool

	retentionOID oid.ID
	setRetention bool
	untilDate    string
	isCompliance bool
}

func (l *LockInfo) SetLegalHold(objID oid.ID) {
	l.legalHoldOID = objID
	l.setLegalHold = true
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
