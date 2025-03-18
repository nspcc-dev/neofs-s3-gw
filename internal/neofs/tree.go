package neofs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs/services/tree"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type (
	TreeClient struct {
		key     *keys.PrivateKey
		conn    *grpc.ClientConn
		service tree.TreeServiceClient
	}

	TreeNode struct {
		ID        uint64
		ParentID  uint64
		ObjID     oid.ID
		TimeStamp uint64
		Size      int64
		Meta      map[string]string
	}

	getNodesParams struct {
		BktInfo    *data.BucketInfo
		TreeID     string
		Path       []string
		Meta       []string
		LatestOnly bool
		AllAttrs   bool
	}
)

const (
	versioningKV        = "Versioning"
	lockConfigurationKV = "LockConfiguration"
	oidKV               = "OID"
	fileNameKV          = "FileName"
	sizeKV              = "Size"

	settingsFileName      = "bucket-settings"
	notifConfFileName     = "bucket-notifications"
	corsFilename          = "bucket-cors"
	bucketTaggingFilename = "bucket-tagging"

	// systemTree -- ID of a tree with system objects
	// i.e. bucket settings with versioning and lock configuration, cors, notifications.
	systemTree = "system"
)

// NewTreeClient creates instance of TreeClient using provided address and create grpc connection.
func NewTreeClient(ctx context.Context, addr string, key *keys.PrivateKey) (*TreeClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %w", err)
	}

	c := tree.NewTreeServiceClient(conn)
	if _, err = c.Healthcheck(ctx, &tree.HealthcheckRequest{}); err != nil {
		return nil, fmt.Errorf("healthcheck: %w", err)
	}

	return &TreeClient{
		key:     key,
		conn:    conn,
		service: c,
	}, nil
}

type NodeResponse interface {
	GetMeta() []*tree.KeyValue
	GetNodeId() uint64
	GetParentId() uint64
	GetTimestamp() uint64
}

func newTreeNode(nodeInfo NodeResponse) (*TreeNode, error) {
	treeNode := &TreeNode{
		ID:        nodeInfo.GetNodeId(),
		ParentID:  nodeInfo.GetParentId(),
		TimeStamp: nodeInfo.GetTimestamp(),
		Meta:      make(map[string]string, len(nodeInfo.GetMeta())),
	}

	for _, kv := range nodeInfo.GetMeta() {
		switch kv.GetKey() {
		case oidKV:
			if err := treeNode.ObjID.DecodeString(string(kv.GetValue())); err != nil {
				return nil, err
			}
		case sizeKV:
			if sizeStr := string(kv.GetValue()); len(sizeStr) > 0 {
				var err error
				if treeNode.Size, err = strconv.ParseInt(sizeStr, 10, 64); err != nil {
					return nil, fmt.Errorf("invalid size value '%s': %w", sizeStr, err)
				}
			}
		default:
			treeNode.Meta[kv.GetKey()] = string(kv.GetValue())
		}
	}

	return treeNode, nil
}

func (n *TreeNode) Get(key string) (string, bool) {
	value, ok := n.Meta[key]
	return value, ok
}

func (n *TreeNode) FileName() (string, bool) {
	value, ok := n.Meta[fileNameKV]
	return value, ok
}

func (c *TreeClient) GetSettingsNode(ctx context.Context, bktInfo *data.BucketInfo) (*data.BucketSettings, error) {
	keysToReturn := []string{versioningKV, lockConfigurationKV}
	node, err := c.getSystemNode(ctx, bktInfo, []string{settingsFileName}, keysToReturn)
	if err != nil {
		return nil, fmt.Errorf("couldn't get node: %w", err)
	}

	settings := &data.BucketSettings{Versioning: data.VersioningUnversioned}
	if versioningValue, ok := node.Get(versioningKV); ok {
		settings.Versioning = versioningValue
	}

	if lockConfigurationValue, ok := node.Get(lockConfigurationKV); ok {
		if settings.LockConfiguration, err = parseLockConfiguration(lockConfigurationValue); err != nil {
			return nil, fmt.Errorf("settings node: invalid lock configuration: %w", err)
		}
	}

	return settings, nil
}

func (c *TreeClient) PutSettingsNode(ctx context.Context, bktInfo *data.BucketInfo, settings *data.BucketSettings) error {
	node, err := c.getSystemNode(ctx, bktInfo, []string{settingsFileName}, []string{})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return fmt.Errorf("couldn't get node: %w", err)
	}

	meta := metaFromSettings(settings)

	if isErrNotFound {
		_, err = c.addNode(ctx, bktInfo, systemTree, 0, meta)
		return err
	}

	return c.moveNode(ctx, bktInfo, systemTree, node.ID, 0, meta)
}

func (c *TreeClient) GetNotificationConfigurationNode(ctx context.Context, bktInfo *data.BucketInfo) (oid.ID, error) {
	node, err := c.getSystemNode(ctx, bktInfo, []string{notifConfFileName}, []string{oidKV})
	if err != nil {
		return oid.ID{}, err
	}

	return node.ObjID, nil
}

func (c *TreeClient) PutNotificationConfigurationNode(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (oid.ID, error) {
	node, err := c.getSystemNode(ctx, bktInfo, []string{notifConfFileName}, []string{oidKV})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return oid.ID{}, fmt.Errorf("couldn't get node: %w", err)
	}

	meta := make(map[string]string)
	meta[fileNameKV] = notifConfFileName
	meta[oidKV] = objID.EncodeToString()

	if isErrNotFound {
		if _, err = c.addNode(ctx, bktInfo, systemTree, 0, meta); err != nil {
			return oid.ID{}, err
		}
		return oid.ID{}, layer.ErrNoNodeToRemove
	}

	return node.ObjID, c.moveNode(ctx, bktInfo, systemTree, node.ID, 0, meta)
}

func (c *TreeClient) GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (oid.ID, error) {
	node, err := c.getSystemNode(ctx, bktInfo, []string{corsFilename}, []string{oidKV})
	if err != nil {
		return oid.ID{}, err
	}

	return node.ObjID, nil
}

func (c *TreeClient) PutBucketCORS(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (oid.ID, error) {
	node, err := c.getSystemNode(ctx, bktInfo, []string{corsFilename}, []string{oidKV})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return oid.ID{}, fmt.Errorf("couldn't get node: %w", err)
	}

	meta := make(map[string]string)
	meta[fileNameKV] = corsFilename
	meta[oidKV] = objID.EncodeToString()

	if isErrNotFound {
		if _, err = c.addNode(ctx, bktInfo, systemTree, 0, meta); err != nil {
			return oid.ID{}, err
		}
		return oid.ID{}, layer.ErrNoNodeToRemove
	}

	return node.ObjID, c.moveNode(ctx, bktInfo, systemTree, node.ID, 0, meta)
}

func (c *TreeClient) DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (oid.ID, error) {
	node, err := c.getSystemNode(ctx, bktInfo, []string{corsFilename}, []string{oidKV})
	if err != nil && !errors.Is(err, layer.ErrNodeNotFound) {
		return oid.ID{}, err
	}

	if node != nil {
		return node.ObjID, c.removeNode(ctx, bktInfo, systemTree, node.ID)
	}

	return oid.ID{}, layer.ErrNoNodeToRemove
}

func (c *TreeClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func metaFromSettings(settings *data.BucketSettings) map[string]string {
	results := make(map[string]string, 3)

	results[fileNameKV] = settingsFileName
	results[versioningKV] = settings.Versioning
	results[lockConfigurationKV] = encodeLockConfiguration(settings.LockConfiguration)

	return results
}

func (c *TreeClient) getSystemNode(ctx context.Context, bktInfo *data.BucketInfo, path, meta []string) (*TreeNode, error) {
	return c.getNode(ctx, bktInfo, systemTree, path, meta, false)
}

func (c *TreeClient) getNode(ctx context.Context, bktInfo *data.BucketInfo, treeID string, path, meta []string, allAttrs bool) (*TreeNode, error) {
	p := &getNodesParams{
		BktInfo:    bktInfo,
		TreeID:     treeID,
		Path:       path,
		Meta:       meta,
		LatestOnly: false,
		AllAttrs:   allAttrs,
	}
	nodes, err := c.getNodes(ctx, p)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, layer.ErrNodeNotFound
	}
	if len(nodes) != 1 {
		return nil, fmt.Errorf("found more than one node")
	}

	return newTreeNode(nodes[0])
}

func (c *TreeClient) getNodes(ctx context.Context, p *getNodesParams) ([]*tree.GetNodeByPathResponse_Info, error) {
	request := &tree.GetNodeByPathRequest{
		Body: &tree.GetNodeByPathRequest_Body{
			ContainerId:   p.BktInfo.CID[:],
			TreeId:        p.TreeID,
			Path:          p.Path,
			Attributes:    p.Meta,
			PathAttribute: fileNameKV,
			LatestOnly:    p.LatestOnly,
			AllAttributes: p.AllAttrs,
			BearerToken:   getBearer(ctx, p.BktInfo),
		},
	}

	if err := c.signRequest(request.Body, func(key, sign []byte) {
		request.Signature = &tree.Signature{
			Key:  key,
			Sign: sign,
		}
	}); err != nil {
		return nil, err
	}

	resp, err := c.service.GetNodeByPath(ctx, request)
	if err != nil {
		return nil, handleError("failed to get node by path", err)
	}

	return resp.GetBody().GetNodes(), nil
}

func handleError(msg string, err error) error {
	if strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("%w: %s", layer.ErrNodeNotFound, err.Error())
	} else if strings.Contains(err.Error(), "is denied by") {
		return fmt.Errorf("%w: %s", layer.ErrNodeAccessDenied, err.Error())
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func getBearer(ctx context.Context, bktInfo *data.BucketInfo) []byte {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		if bd.Gate.BearerToken != nil {
			if bktInfo.Owner == bd.Gate.BearerToken.ResolveIssuer() {
				return bd.Gate.BearerToken.Marshal()
			}
		}
	}
	return nil
}

func (c *TreeClient) addNode(ctx context.Context, bktInfo *data.BucketInfo, treeID string, parent uint64, meta map[string]string) (uint64, error) {
	request := &tree.AddRequest{
		Body: &tree.AddRequest_Body{
			ContainerId: bktInfo.CID[:],
			TreeId:      treeID,
			ParentId:    parent,
			Meta:        metaToKV(meta),
			BearerToken: getBearer(ctx, bktInfo),
		},
	}
	if err := c.signRequest(request.Body, func(key, sign []byte) {
		request.Signature = &tree.Signature{
			Key:  key,
			Sign: sign,
		}
	}); err != nil {
		return 0, err
	}

	resp, err := c.service.Add(ctx, request)
	if err != nil {
		return 0, handleError("failed to add node", err)
	}

	return resp.GetBody().GetNodeId(), nil
}

func (c *TreeClient) moveNode(ctx context.Context, bktInfo *data.BucketInfo, treeID string, nodeID, parentID uint64, meta map[string]string) error {
	request := &tree.MoveRequest{
		Body: &tree.MoveRequest_Body{
			ContainerId: bktInfo.CID[:],
			TreeId:      treeID,
			NodeId:      nodeID,
			ParentId:    parentID,
			Meta:        metaToKV(meta),
			BearerToken: getBearer(ctx, bktInfo),
		},
	}

	if err := c.signRequest(request.Body, func(key, sign []byte) {
		request.Signature = &tree.Signature{
			Key:  key,
			Sign: sign,
		}
	}); err != nil {
		return err
	}

	if _, err := c.service.Move(ctx, request); err != nil {
		return handleError("failed to move node", err)
	}

	return nil
}

func (c *TreeClient) removeNode(ctx context.Context, bktInfo *data.BucketInfo, treeID string, nodeID uint64) error {
	request := &tree.RemoveRequest{
		Body: &tree.RemoveRequest_Body{
			ContainerId: bktInfo.CID[:],
			TreeId:      treeID,
			NodeId:      nodeID,
			BearerToken: getBearer(ctx, bktInfo),
		},
	}
	if err := c.signRequest(request.Body, func(key, sign []byte) {
		request.Signature = &tree.Signature{
			Key:  key,
			Sign: sign,
		}
	}); err != nil {
		return err
	}

	if _, err := c.service.Remove(ctx, request); err != nil {
		return handleError("failed to remove node", err)
	}

	return nil
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
