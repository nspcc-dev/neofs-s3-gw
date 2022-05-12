package layer

import (
	"context"
	"errors"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
)

// TreeService provide interface to interact with tree service using s3 data models.
type TreeService interface {
	// PutSettingsNode update or create new settings node in tree service.
	PutSettingsNode(context.Context, *cid.ID, string, *data.BucketSettings) error

	// GetSettingsNode retrieves the settings node from the tree service and form data.BucketSettings.
	//
	// If node is not found returns ErrNodeNotFound error.
	GetSettingsNode(context.Context, *cid.ID, string) (*data.BucketSettings, error)
}

// ErrNodeNotFound is returned from Tree service in case of not found error.
var ErrNodeNotFound = errors.New("not found")
