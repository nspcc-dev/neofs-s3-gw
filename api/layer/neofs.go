package layer

import (
	"context"
	"errors"
	"hash"
	"io"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// PrmContainerCreate groups parameters of NeoFS.CreateContainer operation.
type PrmContainerCreate struct {
	// NeoFS identifier of the container creator.
	Creator user.ID

	// Public key of the container creator.
	CreatorPubKey keys.PublicKey

	// Container placement policy.
	Policy netmap.PlacementPolicy

	// Name for the container.
	Name string

	// CreationTime value for Timestamp attribute
	CreationTime time.Time

	// Token of the container's creation session. Nil means session absence.
	SessionToken *session.Container

	// Basic ACL of the container.
	BasicACL acl.Basic

	// Attributes for optional parameters.
	AdditionalAttributes [][2]string
}

// PrmAuth groups authentication parameters for the NeoFS operation.
type PrmAuth struct {
	// Bearer token to be used for the operation. Overlaps PrivateKey. Optional.
	BearerToken *bearer.Token
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
	Creator user.ID

	// Key-value object attributes.
	Attributes [][2]string

	// Value for Timestamp attribute (optional).
	CreationTime time.Time

	// List of ids to lock (optional).
	Locks []oid.ID

	// Full payload size (optional).
	PayloadSize uint64

	// Associated filepath (optional).
	Filepath string

	// Object payload encapsulated in io.Reader primitive.
	Payload io.Reader

	// Number of object copies that is enough to consider put successful.
	CopiesNumber uint32

	Multipart *Multipart
}

// Multipart contains info for local object slicing inside s3-gate during multipart upload operation.
type Multipart struct {
	// MultipartHashes contains hashes for the multipart object payload calculation (optional).
	MultipartHashes []hash.Hash
	// SplitID contains splitID for multipart object (optional).
	SplitID string
	// SplitPreviousID contains [oid.ID] of previous object in chain (optional).
	SplitPreviousID *oid.ID
	// Children contains all objects in multipart chain, for linking object (optional).
	Children []oid.ID
	// HeaderObject is a virtual representation of complete multipart object (optional). It is used to set Parent in
	// linking object.
	HeaderObject *object.Object
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

// ErrMetaEmptyParameterValue describes situation when meta parameter was passed but with empty value.
var ErrMetaEmptyParameterValue = errors.New("meta empty parameter value")

// ErrTooManyObjectForDeletion is returned if user is trying to delete to many objects per request.
var ErrTooManyObjectForDeletion = errors.New("to many objects for deletion")

// NeoFS represents virtual connection to NeoFS network.
type NeoFS interface {
	// CreateContainer creates and saves parameterized container in NeoFS.
	// It sets 'Timestamp' attribute to the current time.
	// It returns the ID of the saved container.
	//
	// Created container is public with enabled ACL extension.
	//
	// It returns exactly one non-zero value. It returns any error encountered which
	// prevented the container from being created.
	CreateContainer(context.Context, PrmContainerCreate) (cid.ID, error)

	// Container reads a container from NeoFS by ID.
	//
	// It returns exactly one non-nil value. It returns any error encountered which
	// prevented the container from being read.
	Container(context.Context, cid.ID) (*container.Container, error)

	// UserContainers reads a list of the containers owned by the specified user.
	//
	// It returns exactly one non-nil value. It returns any error encountered which
	// prevented the containers from being listed.
	UserContainers(context.Context, user.ID) ([]cid.ID, error)

	// SetContainerEACL saves the eACL table of the container in NeoFS. The
	// extended ACL is modified within session if session token is not nil.
	//
	// It returns any error encountered which prevented the eACL from being saved.
	SetContainerEACL(context.Context, eacl.Table, *session.Container) error

	// ContainerEACL reads the container eACL from NeoFS by the container ID.
	//
	// It returns exactly one non-nil value. It returns any error encountered which
	// prevented the eACL from being read.
	ContainerEACL(context.Context, cid.ID) (*eacl.Table, error)

	// DeleteContainer marks the container to be removed from NeoFS by ID.
	// Request is sent within session if the session token is specified.
	// Successful return does not guarantee actual removal.
	//
	// It returns any error encountered which prevented the removal request from being sent.
	DeleteContainer(context.Context, cid.ID, *session.Container) error

	// ReadObject reads a part of the object from the NeoFS container by identifier.
	// Exact part is returned according to the parameters:
	//   * with header only: empty payload (both in-mem and reader parts are nil);
	//   * with payload only: header is nil (zero range means full payload);
	//   * with header and payload: full in-mem object, payload reader is nil.
	//
	// WithHeader or WithPayload is true. Range length is positive if offset is positive.
	//
	// Payload reader should be closed if it is no longer needed.
	//
	// It returns ErrAccessDenied on read access violation.
	//
	// It returns exactly one non-nil value. It returns any error encountered which
	// prevented the object header from being read.
	ReadObject(context.Context, PrmObjectRead) (*ObjectPart, error)

	// CreateObject creates and saves a parameterized object in the NeoFS container.
	// It sets 'Timestamp' attribute to the current time.
	// It returns the ID of the saved object.
	//
	// Creation time should be written into the object (UTC).
	//
	// It returns ErrAccessDenied on write access violation.
	//
	// It returns exactly one non-zero value. It returns any error encountered which
	// prevented the container from being created.
	CreateObject(context.Context, PrmObjectCreate) (oid.ID, error)

	// FinalizeObjectWithPayloadChecksums fills and signs header object for complete multipart object.
	FinalizeObjectWithPayloadChecksums(context.Context, object.Object, hash.Hash, hash.Hash, uint64) (*object.Object, error)

	// DeleteObject marks the object to be removed from the NeoFS container by identifier.
	// Successful return does not guarantee actual removal.
	//
	// It returns ErrAccessDenied on remove access violation.
	//
	// It returns any error encountered which prevented the removal request from being sent.
	DeleteObject(context.Context, PrmObjectDelete) error

	// TimeToEpoch computes current epoch and the epoch that corresponds to the provided now and future time.
	// Note:
	// * future time must be after the now
	// * future time will be ceil rounded to match epoch
	//
	// It returns any error encountered which prevented computing epochs.
	TimeToEpoch(ctx context.Context, now time.Time, future time.Time) (uint64, uint64, error)

	// MaxObjectSize returns configured payload size limit for object slicing when enabled.
	MaxObjectSize() int64

	// IsHomomorphicHashingEnabled shows if homomorphic hashing is enabled in config.
	IsHomomorphicHashingEnabled() bool
}
