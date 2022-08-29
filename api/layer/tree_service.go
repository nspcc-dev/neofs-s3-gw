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
	PutSettingsNode(context.Context, cid.ID, *data.BucketSettings) error

	// GetSettingsNode retrieves the settings node from the tree service and form data.BucketSettings.
	//
	// If tree node is not found returns ErrNodeNotFound error.
	GetSettingsNode(context.Context, cid.ID) (*data.BucketSettings, error)

	// GetNotificationConfigurationNode gets an object id that corresponds to object with bucket CORS.
	//
	// If tree node is not found returns ErrNodeNotFound error.
	GetNotificationConfigurationNode(ctx context.Context, cnrID cid.ID) (oid.ID, error)

	// PutNotificationConfigurationNode puts a node to a system tree
	// and returns objectID of a previous notif config which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	PutNotificationConfigurationNode(ctx context.Context, cnrID cid.ID, objID oid.ID) (oid.ID, error)

	// GetBucketCORS gets an object id that corresponds to object with bucket CORS.
	//
	// If object id is not found returns ErrNodeNotFound error.
	GetBucketCORS(ctx context.Context, cnrID cid.ID) (oid.ID, error)

	// PutBucketCORS puts a node to a system tree and returns objectID of a previous cors config which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	PutBucketCORS(ctx context.Context, cnrID cid.ID, objID oid.ID) (oid.ID, error)

	// DeleteBucketCORS removes a node from a system tree and returns objID which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	DeleteBucketCORS(ctx context.Context, cnrID cid.ID) (oid.ID, error)

	GetObjectTagging(ctx context.Context, cnrID cid.ID, objVersion *data.NodeVersion) (map[string]string, error)
	PutObjectTagging(ctx context.Context, cnrID cid.ID, objVersion *data.NodeVersion, tagSet map[string]string) error
	DeleteObjectTagging(ctx context.Context, cnrID cid.ID, objVersion *data.NodeVersion) error

	GetBucketTagging(ctx context.Context, cnrID cid.ID) (map[string]string, error)
	PutBucketTagging(ctx context.Context, cnrID cid.ID, tagSet map[string]string) error
	DeleteBucketTagging(ctx context.Context, cnrID cid.ID) error

	GetVersions(ctx context.Context, cnrID cid.ID, objectName string) ([]*data.NodeVersion, error)
	GetLatestVersion(ctx context.Context, cnrID cid.ID, objectName string) (*data.NodeVersion, error)
	GetLatestVersionsByPrefix(ctx context.Context, cnrID cid.ID, prefix string) ([]*data.NodeVersion, error)
	GetAllVersionsByPrefix(ctx context.Context, cnrID cid.ID, prefix string) ([]*data.NodeVersion, error)
	GetUnversioned(ctx context.Context, cnrID cid.ID, objectName string) (*data.NodeVersion, error)
	AddVersion(ctx context.Context, cnrID cid.ID, newVersion *data.NodeVersion) (uint64, error)
	RemoveVersion(ctx context.Context, cnrID cid.ID, nodeID uint64) error

	PutLock(ctx context.Context, cnrID cid.ID, nodeID uint64, lock *data.LockInfo) error
	GetLock(ctx context.Context, cnrID cid.ID, nodeID uint64) (*data.LockInfo, error)

	CreateMultipartUpload(ctx context.Context, cnrID cid.ID, info *data.MultipartInfo) error
	DeleteMultipartUpload(ctx context.Context, cnrID cid.ID, multipartNodeID uint64) error
	GetMultipartUploadsByPrefix(ctx context.Context, cnrID cid.ID, prefix string) ([]*data.MultipartInfo, error)
	GetMultipartUpload(ctx context.Context, cnrID cid.ID, objectName, uploadID string) (*data.MultipartInfo, error)

	// AddPart puts a node to a system tree as a child of appropriate multipart upload
	// and returns objectID of a previous part which must be deleted in NeoFS.
	//
	// If object id to remove is not found returns ErrNoNodeToRemove error.
	AddPart(ctx context.Context, cnrID cid.ID, multipartNodeID uint64, info *data.PartInfo) (oldObjIDToDelete oid.ID, err error)
	GetParts(ctx context.Context, cnrID cid.ID, multipartNodeID uint64) ([]*data.PartInfo, error)

	// Compound methods for optimizations

	// GetObjectTaggingAndLock unifies GetObjectTagging and GetLock methods in single tree service invocation.
	GetObjectTaggingAndLock(ctx context.Context, cnrID cid.ID, objVersion *data.NodeVersion) (map[string]string, *data.LockInfo, error)
}

var (
	// ErrNodeNotFound is returned from Tree service in case of not found error.
	ErrNodeNotFound = errors.New("not found")

	// ErrNoNodeToRemove is returned from Tree service in case of the lack of node with OID to remove.
	ErrNoNodeToRemove = errors.New("no node to remove")
)
