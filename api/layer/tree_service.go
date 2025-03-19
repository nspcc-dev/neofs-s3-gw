package layer

import (
	"context"
	"errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
)

// TreeService provide interface to interact with tree service using s3 data models.
type TreeService interface {
	// PutSettingsNode update or create new settings node in tree service.
	PutSettingsNode(ctx context.Context, bktInfo *data.BucketInfo, settings *data.BucketSettings) error

	// GetSettingsNode retrieves the settings node from the tree service and form data.BucketSettings.
	//
	// If tree node is not found returns ErrNodeNotFound error.
	GetSettingsNode(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error)
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
