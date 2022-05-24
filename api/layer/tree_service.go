package layer

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
	PutSettingsNode(context.Context, *cid.ID, *data.BucketSettings) error

	// GetSettingsNode retrieves the settings node from the tree service and form data.BucketSettings.
	//
	// If node is not found returns ErrNodeNotFound error.
	GetSettingsNode(context.Context, *cid.ID) (*data.BucketSettings, error)

	GetNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID) (*oid.ID, error)
	// PutNotificationConfigurationNode puts a node to a system tree
	// and returns objectID of a previous notif config which must be deleted in NeoFS
	PutNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error)

	GetBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error)
	// PutBucketCORS puts a node to a system tree and returns objectID of a previous cors config which must be deleted in NeoFS
	PutBucketCORS(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error)
	// DeleteBucketCORS removes a node from a system tree and returns objID which must be deleted in NeoFS
	DeleteBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error)

	GetObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) (map[string]string, error)
	PutObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion, tagSet map[string]string) error
	DeleteObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) error

	GetBucketTagging(ctx context.Context, cnrID *cid.ID) (map[string]string, error)
	PutBucketTagging(ctx context.Context, cnrID *cid.ID, tagSet map[string]string) error
	DeleteBucketTagging(ctx context.Context, cnrID *cid.ID) error

	GetVersions(ctx context.Context, cnrID *cid.ID, objectName string) ([]*data.NodeVersion, error)
	GetLatestVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*data.NodeVersion, error)
	GetLatestVersionsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]oid.ID, error)
	GetAllVersionsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]*data.NodeVersion, error)
	GetUnversioned(ctx context.Context, cnrID *cid.ID, objectName string) (*data.NodeVersion, error)
	AddVersion(ctx context.Context, cnrID *cid.ID, objectName string, newVersion *data.NodeVersion) error
	RemoveVersion(ctx context.Context, cnrID *cid.ID, nodeID uint64) error

	AddSystemVersion(ctx context.Context, cnrID *cid.ID, objectName string, newVersion *data.BaseNodeVersion) error
	GetSystemVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*data.BaseNodeVersion, error)
	RemoveSystemVersion(ctx context.Context, cnrID *cid.ID, nodeID uint64) error

	CreateMultipart(ctx context.Context, cnrID *cid.ID, info *data.MultipartInfo) error
	GetMultipartUploadsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]*data.MultipartInfo, error)
}

// ErrNodeNotFound is returned from Tree service in case of not found error.
var ErrNodeNotFound = errors.New("not found")
