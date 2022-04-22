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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type TreeClient struct {
	conn    *grpc.ClientConn
	service tree.TreeServiceClient
}

type Node struct {
	id   uint64
	meta map[string]string
}

const (
	versioningEnabledKV = "versioning_enabled"
	lockConfigurationKV = "lock_configuration"
	fileNameKV          = "FileName"
	systemNameKV        = "SystemName"

	settingsFileName = "bucket-settings"
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

func newNode(nodeInfo *tree.GetNodeByPathResponse_Info) *Node {
	meta := make(map[string]string, len(nodeInfo.GetMeta()))

	for _, kv := range nodeInfo.GetMeta() {
		meta[kv.GetKey()] = string(kv.GetValue())
	}

	return &Node{
		id:   nodeInfo.GetNodeId(),
		meta: meta,
	}
}

func (n *Node) ID() uint64 {
	return n.id
}

func (n *Node) Meta() map[string]string {
	return n.meta
}

func (n *Node) Get(key string) (string, bool) {
	value, ok := n.meta[key]
	return value, ok
}

func (c *TreeClient) GetSettingsNode(ctx context.Context, cnrID *cid.ID, treeID string) (*data.BucketSettings, error) {
	keysToReturn := []string{versioningEnabledKV, lockConfigurationKV}
	path := []string{settingsFileName}
	node, err := c.getSystemNode(ctx, cnrID, treeID, path, keysToReturn)
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

func (c *TreeClient) PutSettingsNode(ctx context.Context, cnrID *cid.ID, treeID string, settings *data.BucketSettings) error {
	path := []string{settingsFileName}
	node, err := c.getSystemNode(ctx, cnrID, treeID, path, []string{})
	isErrNotFound := errors.Is(err, layer.ErrNotFound)
	if err != nil && !isErrNotFound {
		return fmt.Errorf("couldn't get node: %w", err)
	}

	meta := metaFromSettings(settings)

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, treeID, 0, meta)
		return err
	}

	return c.moveNode(ctx, cnrID, treeID, node.ID(), 0, meta)
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

func (c *TreeClient) getSystemNode(ctx context.Context, cnrID *cid.ID, treeID string, path, meta []string) (*Node, error) {
	return c.getNode(ctx, cnrID, treeID, systemNameKV, path, meta)
}

func (c *TreeClient) getRegularNode(ctx context.Context, cnrID *cid.ID, treeID string, path, meta []string) (*Node, error) {
	return c.getNode(ctx, cnrID, treeID, fileNameKV, path, meta)
}

func (c *TreeClient) getNode(ctx context.Context, cnrID *cid.ID, treeID, pathAttr string, path, meta []string) (*Node, error) {
	nodes, err := c.getNodes(ctx, cnrID, treeID, pathAttr, path, meta)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, layer.ErrNotFound
		}
		return nil, fmt.Errorf("couldn't get nodes: %w", err)
	}
	if len(nodes) == 0 {
		return nil, layer.ErrNotFound
	}
	if len(nodes) != 1 {
		return nil, fmt.Errorf("found more than one node")
	}

	return newNode(nodes[0]), nil
}

func (c *TreeClient) getNodes(ctx context.Context, cnrID *cid.ID, treeID, pathAttr string, path, meta []string) ([]*tree.GetNodeByPathResponse_Info, error) {
	request := &tree.GetNodeByPathRequest{
		Body: &tree.GetNodeByPathRequest_Body{
			ContainerId:   []byte(cnrID.EncodeToString()),
			TreeId:        treeID,
			Path:          path,
			Attributes:    meta,
			PathAttribute: pathAttr,
		},
	}

	resp, err := c.service.GetNodeByPath(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get node path: %w", err)
	}

	return resp.GetBody().GetNodes(), nil
}

func (c *TreeClient) addNode(ctx context.Context, cnrID *cid.ID, treeID string, parent uint64, meta map[string]string) (uint64, error) {
	request := &tree.AddRequest{
		Body: &tree.AddRequest_Body{
			ContainerId: []byte(cnrID.EncodeToString()),
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
			ContainerId: []byte(cnrID.EncodeToString()),
			TreeId:      treeID,
			NodeId:      nodeID,
			ParentId:    parentID,
			Meta:        metaToKV(meta),
		},
	}

	_, err := c.service.Move(ctx, request)
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
