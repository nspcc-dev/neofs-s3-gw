package layer

import (
	"context"
	"errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// TreeService provide interface to interact with tree service using s3 data models.
type TreeService interface {
	// PutSettingsNode update or create new settings node in tree service.
	PutSettingsNode(ctx context.Context, bktInfo *data.BucketInfo, settings *data.BucketSettings) error

	// GetSettingsNode retrieves the settings node from the tree service and form data.BucketSettings.
	//
	// If tree node is not found returns ErrNodeNotFound error.
	GetSettingsNode(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error)

	// GetNotificationConfigurationNode gets an object id that corresponds to object with bucket CORS.
	//
	// If tree node is not found returns ErrNodeNotFound error.
	GetNotificationConfigurationNode(ctx context.Context, bktInfo *data.BucketInfo) (oid.ID, error)

	// PutNotificationConfigurationNode puts a node to a system tree
	// and returns objectID of a previous notif config which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	PutNotificationConfigurationNode(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (oid.ID, error)

	// GetBucketCORS gets an object id that corresponds to object with bucket CORS.
	//
	// If object id is not found returns ErrNodeNotFound error.
	GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (oid.ID, error)

	// PutBucketCORS puts a node to a system tree and returns objectID of a previous cors config which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	PutBucketCORS(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (oid.ID, error)

	// DeleteBucketCORS removes a node from a system tree and returns objID which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (oid.ID, error)
}

var (
	// ErrNodeNotFound is returned from Tree service in case of not found error.
	ErrNodeNotFound = errors.New("not found")

	// ErrNodeAccessDenied is returned from Tree service in case of access denied error.
	ErrNodeAccessDenied = errors.New("access denied")

	// ErrNoNodeToRemove is returned from Tree service in case of the lack of node with OID to remove.
	ErrNoNodeToRemove = errors.New("no node to remove")

	// ErrPartListIsEmpty is returned if no parts available for the upload.
	ErrPartListIsEmpty = errors.New("part list is empty")
)
