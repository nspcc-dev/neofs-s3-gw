package neofs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs/services/tree"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type (
	TreeClient struct {
		conn    *grpc.ClientConn
		service tree.TreeServiceClient
	}

	TreeNode struct {
		ID        uint64
		ObjID     *oid.ID
		TimeStamp uint64
		Meta      map[string]string
	}
)

const (
	versioningEnabledKV = "versioning_enabled"
	lockConfigurationKV = "lock_configuration"
	oidKv               = "OID"
	fileNameKV          = "FileName"
	systemNameKV        = "SystemName"

	settingsFileName  = "bucket-settings"
	notifConfFileName = "bucket-notifications"
	corsFilename      = "bucket-cors"

	// bucketSystemObjectsTreeID -- ID of a tree with system objects for bucket
	// i.e. bucket settings with versioning and lock configuration, cors, notifications
	bucketSystemObjectsTreeID = "system-bucket"
)

// NewTreeClient creates instance of TreeClient using provided address and create grpc connection.
func NewTreeClient(addr string) (*TreeClient, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %v", err)
	}

	c := tree.NewTreeServiceClient(conn)

	return &TreeClient{
		conn:    conn,
		service: c,
	}, nil
}

func newTreeNode(nodeInfo *tree.GetNodeByPathResponse_Info) (*TreeNode, error) {
	var objID *oid.ID
	meta := make(map[string]string, len(nodeInfo.GetMeta()))

	for _, kv := range nodeInfo.GetMeta() {
		if kv.GetKey() == oidKv {
			objID = new(oid.ID)
			err := objID.DecodeString(string(kv.GetValue()))
			if err != nil {
				return nil, err
			}
			continue
		}

		meta[kv.GetKey()] = string(kv.GetValue())
	}

	return &TreeNode{
		ID:        nodeInfo.GetNodeId(),
		ObjID:     objID,
		TimeStamp: nodeInfo.Timestamp,
		Meta:      meta,
	}, nil
}

func (n *TreeNode) Get(key string) (string, bool) {
	value, ok := n.Meta[key]
	return value, ok
}

func (c *TreeClient) GetSettingsNode(ctx context.Context, cnrID *cid.ID) (*data.BucketSettings, error) {
	keysToReturn := []string{versioningEnabledKV, lockConfigurationKV}
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, settingsFileName, keysToReturn)
	if err != nil {
		return nil, fmt.Errorf("couldn't get node: %w", err)
	}

	settings := &data.BucketSettings{}

	if versioningEnabledValue, ok := node.Get(versioningEnabledKV); ok {
		if settings.VersioningEnabled, err = strconv.ParseBool(versioningEnabledValue); err != nil {
			return nil, fmt.Errorf("settings node: invalid versioning: %w", err)
		}
	}

	if lockConfigurationValue, ok := node.Get(lockConfigurationKV); ok {
		if settings.LockConfiguration, err = parseLockConfiguration(lockConfigurationValue); err != nil {
			return nil, fmt.Errorf("settings node: invalid lock configuration: %w", err)
		}
	}

	return settings, nil
}

func (c *TreeClient) PutSettingsNode(ctx context.Context, cnrID *cid.ID, settings *data.BucketSettings) error {
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, settingsFileName, []string{})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return fmt.Errorf("couldn't get node: %w", err)
	}

	meta := metaFromSettings(settings)

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, bucketSystemObjectsTreeID, 0, meta)
		return err
	}

	return c.moveNode(ctx, cnrID, bucketSystemObjectsTreeID, node.ID, 0, meta)
}

func (c *TreeClient) GetNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, notifConfFileName, []string{oidKv})
	if err != nil {
		return nil, err
	}

	return node.ObjID, nil
}

func (c *TreeClient) PutNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, notifConfFileName, []string{oidKv})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return nil, fmt.Errorf("couldn't get node: %w", err)
	}

	meta := make(map[string]string)
	meta[systemNameKV] = notifConfFileName
	meta[oidKv] = objID.EncodeToString()

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, bucketSystemObjectsTreeID, 0, meta)
		return nil, err
	}

	return node.ObjID, c.moveNode(ctx, cnrID, bucketSystemObjectsTreeID, node.ID, 0, meta)
}

func (c *TreeClient) GetBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, corsFilename, []string{oidKv})
	if err != nil {
		return nil, err
	}

	return node.ObjID, nil
}

func (c *TreeClient) PutBucketCORS(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, corsFilename, []string{oidKv})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return nil, fmt.Errorf("couldn't get node: %w", err)
	}

	meta := make(map[string]string)
	meta[systemNameKV] = corsFilename
	meta[oidKv] = objID.EncodeToString()

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, bucketSystemObjectsTreeID, 0, meta)
		return nil, err
	}

	return node.ObjID, c.moveNode(ctx, cnrID, bucketSystemObjectsTreeID, node.ID, 0, meta)
}

func (c *TreeClient) DeleteBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, bucketSystemObjectsTreeID, corsFilename, []string{oidKv})
	if err != nil && !errors.Is(err, layer.ErrNodeNotFound) {
		return nil, err
	}

	if node != nil {
		return node.ObjID, c.removeNode(ctx, cnrID, bucketSystemObjectsTreeID, node.ID)
	}

	return nil, nil
}

func (c *TreeClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func metaFromSettings(settings *data.BucketSettings) map[string]string {
	results := make(map[string]string, 3)

	results[systemNameKV] = settingsFileName
	results[versioningEnabledKV] = strconv.FormatBool(settings.VersioningEnabled)
	results[lockConfigurationKV] = encodeLockConfiguration(settings.LockConfiguration)

	return results
}

func (c *TreeClient) getSystemNode(ctx context.Context, cnrID *cid.ID, treeID, path string, meta []string) (*TreeNode, error) {
	request := &tree.GetNodeByPathRequest{
		Body: &tree.GetNodeByPathRequest_Body{
			ContainerId:   []byte(cnrID.String()),
			TreeId:        treeID,
			Path:          []string{path},
			Attributes:    meta,
			PathAttribute: systemNameKV,
		},
	}
	resp, err := c.service.GetNodeByPath(ctx, request)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, layer.ErrNodeNotFound
		}
		return nil, fmt.Errorf("couldn't get nodes: %w", err)
	}
	if len(resp.Body.GetNodes()) == 0 {
		return nil, layer.ErrNodeNotFound
	}
	if len(resp.Body.GetNodes()) != 1 {
		return nil, fmt.Errorf("found more than one node")
	}

	return newTreeNode(resp.Body.Nodes[0])
}

func (c *TreeClient) addNode(ctx context.Context, cnrID *cid.ID, treeID string, parent uint64, meta map[string]string) (uint64, error) {
	request := &tree.AddRequest{
		Body: &tree.AddRequest_Body{
			ContainerId: []byte(cnrID.String()),
			TreeId:      treeID,
			ParentId:    parent,
			Meta:        metaToKV(meta),
		},
	}

	resp, err := c.service.Add(ctx, request)
	if err != nil {
		return 0, err
	}

	return resp.GetBody().GetNodeId(), nil
}

func (c *TreeClient) moveNode(ctx context.Context, cnrID *cid.ID, treeID string, nodeID, parentID uint64, meta map[string]string) error {
	request := &tree.MoveRequest{
		Body: &tree.MoveRequest_Body{
			ContainerId: []byte(cnrID.String()),
			TreeId:      treeID,
			NodeId:      nodeID,
			ParentId:    parentID,
			Meta:        metaToKV(meta),
		},
	}

	_, err := c.service.Move(ctx, request)
	return err
}

func (c *TreeClient) removeNode(ctx context.Context, cnrID *cid.ID, treeID string, nodeID uint64) error {
	r := &tree.RemoveRequest{
		Body: &tree.RemoveRequest_Body{
			ContainerId: []byte(cnrID.String()),
			TreeId:      treeID,
			NodeId:      nodeID,
		},
	}
	_, err := c.service.Remove(ctx, r)
	return err
}

func metaToKV(meta map[string]string) []*tree.KeyValue {
	result := make([]*tree.KeyValue, 0, len(meta))

	for key, value := range meta {
		result = append(result, &tree.KeyValue{Key: key, Value: []byte(value)})
	}

	return result
}

func parseLockConfiguration(value string) (*data.ObjectLockConfiguration, error) {
	result := &data.ObjectLockConfiguration{}
	if len(value) == 0 {
		return result, nil
	}

	lockValues := strings.Split(value, ",")
	result.ObjectLockEnabled = lockValues[0]

	if len(lockValues) == 1 {
		return result, nil
	}

	if len(lockValues) != 4 {
		return nil, fmt.Errorf("invalid lock configuration: %s", value)
	}

	var err error
	var days, years int64

	if len(lockValues[1]) > 0 {
		if days, err = strconv.ParseInt(lockValues[1], 10, 64); err != nil {
			return nil, fmt.Errorf("invalid lock configuration: %s", value)
		}
	}

	if len(lockValues[3]) > 0 {
		if years, err = strconv.ParseInt(lockValues[3], 10, 64); err != nil {
			return nil, fmt.Errorf("invalid lock configuration: %s", value)
		}
	}

	result.Rule = &data.ObjectLockRule{
		DefaultRetention: &data.DefaultRetention{
			Days:  days,
			Mode:  lockValues[2],
			Years: years,
		},
	}

	return result, nil
}

func encodeLockConfiguration(conf *data.ObjectLockConfiguration) string {
	if conf == nil {
		return ""
	}

	if conf.Rule == nil || conf.Rule.DefaultRetention == nil {
		return conf.ObjectLockEnabled
	}

	defaults := conf.Rule.DefaultRetention
	return fmt.Sprintf("%s,%d,%s,%d", conf.ObjectLockEnabled, defaults.Days, defaults.Mode, defaults.Years)
}
