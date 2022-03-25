package neofs

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/token"
)

// PrmContainerCreate groups parameters of NeoFS.CreateContainer operation.
type PrmContainerCreate struct {
	// NeoFS identifier of the container creator.
	Creator owner.ID

	// Container placement policy.
	Policy netmap.PlacementPolicy

	// Name for the container.
	Name string

	// Token of the container's creation session. Nil means session absence.
	SessionToken *session.Token

	// Basic ACL of the container.
	BasicACL acl.BasicACL

	// Attributes for optional parameters.
	AdditionalAttributes [][2]string
}

// PrmAuth groups authentication parameters for the NeoFS operation.
type PrmAuth struct {
	// Bearer token to be used for the operation. Overlaps PrivateKey. Optional.
	BearerToken *token.BearerToken

	// Private key used for the operation if BearerToken is missing (in this case non-nil).
	PrivateKey *ecdsa.PrivateKey
}

// PrmObjectSelect groups parameters of NeoFS.SelectObjects operation.
type PrmObjectSelect struct {
	// Authentication parameters.
	PrmAuth

	// Container to select the objects from.
	Container cid.ID

	// Key-value object attribute which should exactly be
	// presented in selected objects. Optional, empty key means any.
	ExactAttribute [2]string

	// File prefix of the selected objects. Optional, empty value means any.
	FilePrefix string
}

// PrmObjectRead groups parameters of NeoFS.ReadObject operation.
type PrmObjectRead struct {
	// Authentication parameters.
	PrmAuth

	// Container to read the object header from.
	Container cid.ID

	// ID of the object for which to read the header.
	Object oid.ID

	// Flag to read object header.
	WithHeader bool

	// Flag to read object payload. False overlaps payload range.
	WithPayload bool

	// Offset-length range of the object payload to be read.
	PayloadRange [2]uint64
}

// ObjectPart represents partially read NeoFS object.
type ObjectPart struct {
	// Object header with optional in-memory payload part.
	Head *object.Object

	// Object payload part encapsulated in io.Reader primitive.
	// Returns ErrAccessDenied on read access violation.
	Payload io.ReadCloser
}

// PrmObjectCreate groups parameters of NeoFS.CreateObject operation.
type PrmObjectCreate struct {
	// Authentication parameters.
	PrmAuth

	// Container to store the object.
	Container cid.ID

	// NeoFS identifier of the object creator.
	Creator owner.ID

	// Key-value object attributes.
	Attributes [][2]string

	// List of ids to lock (optional).
	Locks []oid.ID

	// Full payload size (optional).
	PayloadSize uint64

	// Associated filename (optional).
	Filename string

	// Object payload encapsulated in io.Reader primitive.
	Payload io.Reader
}

// PrmObjectDelete groups parameters of NeoFS.DeleteObject operation.
type PrmObjectDelete struct {
	// Authentication parameters.
	PrmAuth

	// Container to delete the object from.
	Container cid.ID

	// Identifier of the removed object.
	Object oid.ID
}

// ErrAccessDenied is returned from NeoFS in case of access violation.
var ErrAccessDenied = errors.New("access denied")

// NeoFS represents virtual connection to NeoFS network.
type NeoFS interface {
	// CreateContainer creates and saves parameterized container in NeoFS.
	// It sets 'Timestamp' attribute to current time.
	// Returns ID of the saved container.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the container to be created.
	CreateContainer(context.Context, PrmContainerCreate) (*cid.ID, error)

	// Container reads container from NeoFS by ID.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the container to be read.
	Container(context.Context, cid.ID) (*container.Container, error)

	// UserContainers reads list of the containers owned by specified user.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the containers to be listed.
	UserContainers(context.Context, owner.ID) ([]cid.ID, error)

	// SetContainerEACL saves eACL table of the container in NeoFS.
	//
	// Returns any error encountered which prevented the eACL to be saved.
	SetContainerEACL(context.Context, eacl.Table) error

	// ContainerEACL reads container eACL from NeoFS by container ID.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the eACL to be read.
	ContainerEACL(context.Context, cid.ID) (*eacl.Table, error)

	// DeleteContainer marks the container to be removed from NeoFS by ID.
	// Request is sent within session if the session token is specified.
	// Successful return does not guarantee the actual removal.
	//
	// Returns any error encountered which prevented the removal request to be sent.
	DeleteContainer(context.Context, cid.ID, *session.Token) error

	// SelectObjects perform object selection from the NeoFS container according
	// to specified parameters. Selects user objects only.
	//
	// Returns ErrAccessDenied on selection access violation.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the objects to be selected.
	SelectObjects(context.Context, PrmObjectSelect) ([]oid.ID, error)

	// ReadObject reads part of the object from the NeoFS container by identifier.
	// Exact part is returned according to the parameters:
	//   * with header only: empty payload (both in-mem and reader parts are nil);
	//   * with payload only: header is nil (zero range means full payload);
	//   * with header and payload: full in-mem object, payload reader is nil.
	//
	// WithHeader or WithPayload is true. Range length is positive if offset is positive.
	//
	// Payload reader should be closed if it is no longer needed.
	//
	// Returns ErrAccessDenied on read access violation.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the object header to be read.
	ReadObject(context.Context, PrmObjectRead) (*ObjectPart, error)

	// CreateObject creates and saves parameterized object in the NeoFS container.
	// It sets 'Timestamp' attribute to current time.
	// Returns ID of the saved object.
	//
	// Creation time should be written into object (UTC).
	//
	// Returns ErrAccessDenied on write access violation.
	//
	// Returns exactly one non-nil value. Returns any error encountered which
	// prevented the container to be created.
	CreateObject(context.Context, PrmObjectCreate) (*oid.ID, error)

	// DeleteObject marks the object to be removed from the NeoFS container by identifier.
	// Successful return does not guarantee the actual removal.
	//
	// Returns ErrAccessDenied on remove access violation.
	//
	// Returns any error encountered which prevented the removal request to be sent.
	DeleteObject(context.Context, PrmObjectDelete) error

	// TimeToEpoch compute current epoch and epoch that corresponds provided time.
	// Note:
	// * time must be in the future
	// * time will be ceil rounded to match epoch
	//
	// Returns any error encountered which prevented computing epochs.
	TimeToEpoch(context.Context, time.Time) (uint64, uint64, error)
}
