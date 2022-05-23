package neofs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs/services/tree"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
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
		ObjID     oid.ID
		TimeStamp uint64
		Meta      map[string]string
	}
)

const (
	versioningEnabledKV = "versioning_enabled"
	lockConfigurationKV = "lock_configuration"
	oidKV               = "OID"
	fileNameKV          = "FileName"
	systemNameKV        = "SystemName"
	isUnversionedKV     = "IsUnversioned"
	isDeleteMarkerKV    = "IdDeleteMarker"

	settingsFileName  = "bucket-settings"
	notifConfFileName = "bucket-notifications"
	corsFilename      = "bucket-cors"
	emptyFileName     = "<empty>" // to handle trailing slash in name

	// versionTree -- ID of a tree with object versions.
	versionTree = "version"

	// systemTree -- ID of a tree with system objects
	// i.e. bucket settings with versioning and lock configuration, cors, notifications.
	systemTree = "system"

	separator = "/"

	maxGetSubTreeDepth = 10 // current limit on storage node side
)

// NewTreeClient creates instance of TreeClient using provided address and create grpc connection.
func NewTreeClient(addr string, key *keys.PrivateKey) (*TreeClient, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %v", err)
	}

	c := tree.NewTreeServiceClient(conn)

	return &TreeClient{
		key:     key,
		conn:    conn,
		service: c,
	}, nil
}

type NodeResponse interface {
	GetMeta() []*tree.KeyValue
	GetNodeId() uint64
	GetTimestamp() uint64
}

func newTreeNode(nodeInfo NodeResponse) (*TreeNode, error) {
	var objID oid.ID
	meta := make(map[string]string, len(nodeInfo.GetMeta()))

	for _, kv := range nodeInfo.GetMeta() {
		if kv.GetKey() == oidKV {
			if err := objID.DecodeString(string(kv.GetValue())); err != nil {
				return nil, err
			}
			continue
		}

		meta[kv.GetKey()] = string(kv.GetValue())
	}

	return &TreeNode{
		ID:        nodeInfo.GetNodeId(),
		ObjID:     objID,
		TimeStamp: nodeInfo.GetTimestamp(),
		Meta:      meta,
	}, nil
}

func (n *TreeNode) Get(key string) (string, bool) {
	value, ok := n.Meta[key]
	return value, ok
}

func newNodeVersion(node NodeResponse) (*layer.NodeVersion, error) {
	treeNode, err := newTreeNode(node)
	if err != nil {
		return nil, fmt.Errorf("invalid tree node: %w", err)
	}

	_, isUnversioned := treeNode.Get(isUnversionedKV)
	_, isDeleteMarker := treeNode.Get(isDeleteMarkerKV)

	return &layer.NodeVersion{
		BaseNodeVersion: layer.BaseNodeVersion{
			ID:  treeNode.ID,
			OID: treeNode.ObjID,
		},
		IsUnversioned:  isUnversioned,
		IsDeleteMarker: isDeleteMarker,
	}, nil
}

func (c *TreeClient) GetSettingsNode(ctx context.Context, cnrID *cid.ID) (*data.BucketSettings, error) {
	keysToReturn := []string{versioningEnabledKV, lockConfigurationKV}
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{settingsFileName}, keysToReturn)
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
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{settingsFileName}, []string{})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return fmt.Errorf("couldn't get node: %w", err)
	}

	meta := metaFromSettings(settings)

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, systemTree, 0, meta)
		return err
	}

	return c.moveNode(ctx, cnrID, systemTree, node.ID, 0, meta)
}

func (c *TreeClient) GetNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{notifConfFileName}, []string{oidKV})
	if err != nil {
		return nil, err
	}

	return &node.ObjID, nil
}

func (c *TreeClient) PutNotificationConfigurationNode(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{notifConfFileName}, []string{oidKV})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return nil, fmt.Errorf("couldn't get node: %w", err)
	}

	meta := make(map[string]string)
	meta[systemNameKV] = notifConfFileName
	meta[oidKV] = objID.EncodeToString()

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, systemTree, 0, meta)
		return nil, err
	}

	return &node.ObjID, c.moveNode(ctx, cnrID, systemTree, node.ID, 0, meta)
}

func (c *TreeClient) GetBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{corsFilename}, []string{oidKV})
	if err != nil {
		return nil, err
	}

	return &node.ObjID, nil
}

func (c *TreeClient) PutBucketCORS(ctx context.Context, cnrID *cid.ID, objID *oid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{corsFilename}, []string{oidKV})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return nil, fmt.Errorf("couldn't get node: %w", err)
	}

	meta := make(map[string]string)
	meta[systemNameKV] = corsFilename
	meta[oidKV] = objID.EncodeToString()

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, systemTree, 0, meta)
		return nil, err
	}

	return &node.ObjID, c.moveNode(ctx, cnrID, systemTree, node.ID, 0, meta)
}

func (c *TreeClient) DeleteBucketCORS(ctx context.Context, cnrID *cid.ID) (*oid.ID, error) {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{corsFilename}, []string{oidKV})
	if err != nil && !errors.Is(err, layer.ErrNodeNotFound) {
		return nil, err
	}

	if node != nil {
		return &node.ObjID, c.removeNode(ctx, cnrID, systemTree, node.ID)
	}

	return nil, nil
}

func (c *TreeClient) GetVersions(ctx context.Context, cnrID *cid.ID, filepath string) ([]*layer.NodeVersion, error) {
	return c.getVersions(ctx, cnrID, versionTree, filepath, false)
}

func (c *TreeClient) GetLatestVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*layer.NodeVersion, error) {
	meta := []string{oidKV, isUnversionedKV, isDeleteMarkerKV}
	path := pathFromName(objectName)

	return c.getLatestVersion(ctx, cnrID, versionTree, fileNameKV, path, meta)
}

// pathFromName splits name by '/' and add an empty marker if name has trailing slash.
func pathFromName(objectName string) []string {
	path := strings.Split(objectName, separator)
	if path[len(path)-1] == "" {
		path[len(path)-1] = emptyFileName
	}
	return path
}

func (c *TreeClient) GetLatestVersionsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]oid.ID, error) {
	var rootID uint64
	path := strings.Split(prefix, separator)
	tailPrefix := path[len(path)-1]

	if len(path) > 1 {
		meta := []string{fileNameKV}

		nodes, err := c.getNodes(ctx, cnrID, versionTree, fileNameKV, path[:len(path)-1], meta, true)
		if err != nil {
			return nil, err
		}
		if len(nodes) == 0 {
			return nil, nil
		}
		if len(nodes) != 1 {
			return nil, layer.ErrNodeNotFound
		}

		rootID = nodes[0].NodeId
	}

	subTree, err := c.getSubTree(ctx, cnrID, versionTree, rootID, 1)
	if err != nil {
		return nil, err
	}

	var result []oid.ID
	for _, node := range subTree {
		if node.GetNodeId() != 0 && hasPrefix(node, tailPrefix) {
			latestNodes, err := c.getSubTreeLatestVersions(ctx, cnrID, node.GetNodeId())
			if err != nil {
				return nil, err
			}
			result = append(result, latestNodes...)
		}
	}

	return result, nil
}

func hasPrefix(node *tree.GetSubTreeResponse_Body, prefix string) bool {
	for _, kv := range node.GetMeta() {
		if kv.GetKey() == fileNameKV {
			return strings.HasPrefix(string(kv.GetValue()), prefix)
		}
	}

	return false
}

func (c *TreeClient) getSubTreeLatestVersions(ctx context.Context, cnrID *cid.ID, nodeID uint64) ([]oid.ID, error) {
	subTree, err := c.getSubTree(ctx, cnrID, versionTree, nodeID, maxGetSubTreeDepth)
	if err != nil {
		return nil, err
	}

	var emptyOID oid.ID

	latestVersions := make(map[string]*TreeNode, len(subTree))
	for _, node := range subTree {
		treeNode, err := newTreeNode(node)
		if err != nil || treeNode.ObjID.Equals(emptyOID) { // invalid OID attribute
			continue
		}
		fileName, ok := treeNode.Get(fileNameKV)
		if !ok {
			continue
		}

		key := formLatestNodeKey(node.GetParentId(), fileName)
		latest, ok := latestVersions[key]
		if !ok || latest.TimeStamp <= treeNode.TimeStamp { // todo also compare oid
			latestVersions[key] = treeNode
		}
	}

	result := make([]oid.ID, 0, len(latestVersions))
	for _, treeNode := range latestVersions {
		if _, ok := treeNode.Get(isDeleteMarkerKV); ok {
			continue
		}
		result = append(result, treeNode.ObjID)
	}

	return result, nil
}

func formLatestNodeKey(parentID uint64, fileName string) string {
	return strconv.FormatUint(parentID, 10) + fileName
}

func (c *TreeClient) GetSystemVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*layer.BaseNodeVersion, error) {
	meta := []string{oidKV}
	path := pathFromName(objectName)

	node, err := c.getLatestVersion(ctx, cnrID, systemTree, systemNameKV, path, meta)
	if err != nil {
		return nil, err
	}
	return &node.BaseNodeVersion, nil
}

func (c *TreeClient) getLatestVersion(ctx context.Context, cnrID *cid.ID, treeID, attrPath string, path, meta []string) (*layer.NodeVersion, error) {
	nodes, err := c.getNodes(ctx, cnrID, treeID, attrPath, path, meta, true)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, layer.ErrNodeNotFound
		}
		return nil, fmt.Errorf("couldn't get nodes: %w", err)
	}

	if len(nodes) == 0 {
		return nil, layer.ErrNodeNotFound
	}

	return newNodeVersion(nodes[0])
}

func (c *TreeClient) GetUnversioned(ctx context.Context, cnrID *cid.ID, filepath string) (*layer.NodeVersion, error) {
	return c.getUnversioned(ctx, cnrID, versionTree, filepath)
}

func (c *TreeClient) getUnversioned(ctx context.Context, cnrID *cid.ID, treeID, filepath string) (*layer.NodeVersion, error) {
	nodes, err := c.getVersions(ctx, cnrID, treeID, filepath, true)
	if err != nil {
		return nil, err
	}

	if len(nodes) > 1 {
		return nil, fmt.Errorf("found more than one unversioned node")
	}

	if len(nodes) != 1 {
		return nil, layer.ErrNodeNotFound
	}

	return nodes[0], nil
}

func (c *TreeClient) AddVersion(ctx context.Context, cnrID *cid.ID, filepath string, version *layer.NodeVersion) error {
	return c.addVersion(ctx, cnrID, versionTree, fileNameKV, filepath, version)
}

func (c *TreeClient) AddSystemVersion(ctx context.Context, cnrID *cid.ID, filepath string, version *layer.BaseNodeVersion) error {
	newVersion := &layer.NodeVersion{
		BaseNodeVersion: *version,
		IsUnversioned:   true,
	}
	return c.addVersion(ctx, cnrID, systemTree, systemNameKV, filepath, newVersion)
}

func (c *TreeClient) RemoveVersion(ctx context.Context, cnrID *cid.ID, id uint64) error {
	return c.removeNode(ctx, cnrID, versionTree, id)
}

func (c *TreeClient) RemoveSystemVersion(ctx context.Context, cnrID *cid.ID, id uint64) error {
	return c.removeNode(ctx, cnrID, systemTree, id)
}

func (c *TreeClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func (c *TreeClient) addVersion(ctx context.Context, cnrID *cid.ID, treeID, attrPath, filepath string, version *layer.NodeVersion) error {
	path := pathFromName(filepath)
	meta := map[string]string{
		oidKV:    version.OID.String(),
		attrPath: path[len(path)-1],
	}

	if version.IsDeleteMarker {
		meta[isDeleteMarkerKV] = "true"
	}

	if version.IsUnversioned {
		meta[isUnversionedKV] = "true"

		node, err := c.getUnversioned(ctx, cnrID, treeID, filepath)
		if err == nil {
			parentID, err := c.getParent(ctx, cnrID, treeID, node.ID)
			if err != nil {
				return err
			}

			return c.moveNode(ctx, cnrID, treeID, node.ID, parentID, meta)
		}

		if !errors.Is(err, layer.ErrNodeNotFound) {
			return err
		}
	}

	return c.addNodeByPath(ctx, cnrID, treeID, path[:len(path)-1], meta)
}

func (c *TreeClient) getVersions(ctx context.Context, cnrID *cid.ID, treeID, filepath string, onlyUnversioned bool) ([]*layer.NodeVersion, error) {
	keysToReturn := []string{oidKV, isUnversionedKV, isDeleteMarkerKV}
	path := pathFromName(filepath)
	nodes, err := c.getNodes(ctx, cnrID, treeID, fileNameKV, path, keysToReturn, false)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("couldn't get nodes: %w", err)
	}

	result := make([]*layer.NodeVersion, 0, len(nodes))
	for _, node := range nodes {
		nodeVersion, err := newNodeVersion(node)
		if err != nil {
			return nil, err
		}

		if onlyUnversioned && !nodeVersion.IsUnversioned {
			continue
		}

		result = append(result, nodeVersion)
	}

	return result, nil
}

func (c *TreeClient) getParent(ctx context.Context, cnrID *cid.ID, treeID string, id uint64) (uint64, error) {
	subTree, err := c.getSubTree(ctx, cnrID, treeID, id, 0)
	if err != nil {
		return 0, err
	}

	return subTree[0].GetParentId(), nil
}

func (c *TreeClient) getSubTree(ctx context.Context, cnrID *cid.ID, treeID string, rootID uint64, depth uint32) ([]*tree.GetSubTreeResponse_Body, error) {
	request := &tree.GetSubTreeRequest{
		Body: &tree.GetSubTreeRequest_Body{
			ContainerId: cnrID[:],
			TreeId:      treeID,
			RootId:      rootID,
			Depth:       depth,
			BearerToken: getBearer(ctx),
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

	cli, err := c.service.GetSubTree(ctx, request)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get sub tree client: %w", err)
	}

	var subtree []*tree.GetSubTreeResponse_Body
	for {
		resp, err := cli.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to get sub tree: %w", err)
		}
		subtree = append(subtree, resp.Body)
	}

	return subtree, nil
}

func metaFromSettings(settings *data.BucketSettings) map[string]string {
	results := make(map[string]string, 3)

	results[systemNameKV] = settingsFileName
	results[versioningEnabledKV] = strconv.FormatBool(settings.VersioningEnabled)
	results[lockConfigurationKV] = encodeLockConfiguration(settings.LockConfiguration)

	return results
}

func (c *TreeClient) getSystemNode(ctx context.Context, cnrID *cid.ID, treeID string, path, meta []string) (*TreeNode, error) {
	return c.getNode(ctx, cnrID, treeID, systemNameKV, path, meta)
}

func (c *TreeClient) getNode(ctx context.Context, cnrID *cid.ID, treeID, pathAttr string, path, meta []string) (*TreeNode, error) {
	nodes, err := c.getNodes(ctx, cnrID, treeID, pathAttr, path, meta, false)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, layer.ErrNodeNotFound
		}
		return nil, fmt.Errorf("couldn't get nodes: %w", err)
	}
	if len(nodes) == 0 {
		return nil, layer.ErrNodeNotFound
	}
	if len(nodes) != 1 {
		return nil, fmt.Errorf("found more than one node")
	}

	return newTreeNode(nodes[0])
}

func (c *TreeClient) getNodes(ctx context.Context, cnrID *cid.ID, treeID, pathAttr string, path, meta []string, latestOnly bool) ([]*tree.GetNodeByPathResponse_Info, error) {
	request := &tree.GetNodeByPathRequest{
		Body: &tree.GetNodeByPathRequest_Body{
			ContainerId:   cnrID[:],
			TreeId:        treeID,
			Path:          path,
			Attributes:    meta,
			PathAttribute: pathAttr,
			LatestOnly:    latestOnly,
			BearerToken:   getBearer(ctx),
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
		return nil, fmt.Errorf("failed to get node path: %w", err)
	}

	return resp.GetBody().GetNodes(), nil
}

func getBearer(ctx context.Context) []byte {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil {
		if bd.Gate.BearerToken != nil {
			return bd.Gate.BearerToken.Marshal()
		}
	}
	return nil
}

func (c *TreeClient) addNode(ctx context.Context, cnrID *cid.ID, treeID string, parent uint64, meta map[string]string) (uint64, error) {
	request := &tree.AddRequest{
		Body: &tree.AddRequest_Body{
			ContainerId: cnrID[:],
			TreeId:      treeID,
			ParentId:    parent,
			Meta:        metaToKV(meta),
			BearerToken: getBearer(ctx),
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
		return 0, err
	}

	return resp.GetBody().GetNodeId(), nil
}

func (c *TreeClient) addNodeByPath(ctx context.Context, cnrID *cid.ID, treeID string, path []string, meta map[string]string) error {
	request := &tree.AddByPathRequest{
		Body: &tree.AddByPathRequest_Body{
			ContainerId:   cnrID[:],
			TreeId:        treeID,
			Path:          path,
			Meta:          metaToKV(meta),
			PathAttribute: fileNameKV,
			BearerToken:   getBearer(ctx),
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

	_, err := c.service.AddByPath(ctx, request)
	return err
}

func (c *TreeClient) moveNode(ctx context.Context, cnrID *cid.ID, treeID string, nodeID, parentID uint64, meta map[string]string) error {
	request := &tree.MoveRequest{
		Body: &tree.MoveRequest_Body{
			ContainerId: cnrID[:],
			TreeId:      treeID,
			NodeId:      nodeID,
			ParentId:    parentID,
			Meta:        metaToKV(meta),
			BearerToken: getBearer(ctx),
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

	_, err := c.service.Move(ctx, request)
	return err
}

func (c *TreeClient) removeNode(ctx context.Context, cnrID *cid.ID, treeID string, nodeID uint64) error {
	request := &tree.RemoveRequest{
		Body: &tree.RemoveRequest_Body{
			ContainerId: cnrID[:],
			TreeId:      treeID,
			NodeId:      nodeID,
			BearerToken: getBearer(ctx),
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

	_, err := c.service.Remove(ctx, request)
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
