package neofs

import (
	"context"
	"errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// TreeService provide interface to interact with tree service using s3 data models.
type TreeService interface {
	// PutSettingsNode update or create new settings node in tree service.
	PutSettingsNode(context.Context, *cid.ID, string, *data.BucketSettings) error

	// GetSettingsNode retrieves the settings node from the tree service and form data.BucketSettings.
	//
	// If node is not found returns ErrNodeNotFound error.
	GetSettingsNode(context.Context, *cid.ID, string) (*data.BucketSettings, error)

	GetNotificationConfigurationNodes(ctx context.Context, cnrID *cid.ID, latestOnly bool) ([]*oid.ID, []uint64, error)
	PutNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID, objID *oid.ID) error
	DeleteNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID, nodeID uint64) error

	GetBucketCORS(ctx context.Context, cnrID *cid.ID, latestOnly bool) ([]*oid.ID, []uint64, error)
	PutBucketCORS(ctx context.Context, cnrID *cid.ID, objID *oid.ID) error
	DeleteBucketCORS(ctx context.Context, cnrID *cid.ID, nodeID uint64) error
}

// ErrNodeNotFound is returned from Tree service in case of not found error.
var ErrNodeNotFound = errors.New("not found")
