package neofs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs/services/tree"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
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

	getNodesParams struct {
		CnrID      *cid.ID
		TreeID     string
		PathAttr   string
		Path       []string
		Meta       []string
		LatestOnly bool
		AllAttrs   bool
	}
)

const (
	versioningEnabledKV = "versioning_enabled"
	lockConfigurationKV = "lock_configuration"
	oidKV               = "OID"
	fileNameKV          = "FileName"
	systemNameKV        = "SystemName"
	isUnversionedKV     = "IsUnversioned"
	isTagKV             = "isTag"

	// keys for delete marker nodes
	isDeleteMarkerKV = "IdDeleteMarker"
	filePathKV       = "FilePath"
	ownerKV          = "Owner"
	createdKV        = "Created"

	settingsFileName      = "bucket-settings"
	notifConfFileName     = "bucket-notifications"
	corsFilename          = "bucket-cors"
	emptyFileName         = "<empty>" // to handle trailing slash in name
	bucketTaggingFilename = "bucket-tagging"

	// versionTree -- ID of a tree with object versions.
	versionTree = "version"

	// systemTree -- ID of a tree with system objects
	// i.e. bucket settings with versioning and lock configuration, cors, notifications.
	systemTree = "system"

	separator            = "/"
	userDefinedtagPrefix = "User-Tag-"

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

func newNodeVersion(node NodeResponse) (*data.NodeVersion, error) {
	treeNode, err := newTreeNode(node)
	if err != nil {
		return nil, fmt.Errorf("invalid tree node: %w", err)
	}

	return newNodeVersionFromTreeNode(treeNode), nil
}

func newNodeVersionFromTreeNode(treeNode *TreeNode) *data.NodeVersion {
	_, isUnversioned := treeNode.Get(isUnversionedKV)
	_, isDeleteMarker := treeNode.Get(isDeleteMarkerKV)

	version := &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			ID:        treeNode.ID,
			OID:       treeNode.ObjID,
			Timestamp: treeNode.TimeStamp,
		},
		IsUnversioned: isUnversioned,
	}

	if isDeleteMarker {
		filePath, _ := treeNode.Get(filePathKV)

		var created time.Time
		if createdStr, ok := treeNode.Get(createdKV); ok {
			if utcMilli, err := strconv.ParseInt(createdStr, 10, 64); err == nil {
				created = time.UnixMilli(utcMilli)
			}
		}

		var owner user.ID
		if ownerStr, ok := treeNode.Get(ownerKV); ok {
			_ = owner.DecodeString(ownerStr)
		}

		version.DeleteMarker = &data.DeleteMarkerInfo{
			FilePath: filePath,
			Created:  created,
			Owner:    owner,
		}
	}
	return version
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

func (c *TreeClient) GetObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) (map[string]string, error) {
	tagNode, err := c.getObjectTaggingNode(ctx, cnrID, objVersion)
	if err != nil {
		return nil, err
	}

	if tagNode == nil {
		return nil, nil
	}

	meta := make(map[string]string)

	for key, val := range tagNode.Meta {
		if strings.HasPrefix(key, userDefinedtagPrefix) {
			meta[strings.TrimPrefix(key, userDefinedtagPrefix)] = val
		}
	}

	return meta, nil
}

func (c *TreeClient) PutObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion, tagSet map[string]string) error {
	tagNode, err := c.getObjectTaggingNode(ctx, cnrID, objVersion)
	if err != nil {
		return err
	}

	treeTagSet := make(map[string]string)
	treeTagSet[isTagKV] = "true"

	for key, val := range tagSet {
		treeTagSet[userDefinedtagPrefix+key] = val
	}

	if tagNode == nil {
		_, err = c.addNode(ctx, cnrID, versionTree, objVersion.ID, treeTagSet)
	} else {
		err = c.moveNode(ctx, cnrID, versionTree, tagNode.ID, objVersion.ID, treeTagSet)
	}

	return err
}

func (c *TreeClient) DeleteObjectTagging(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) error {
	tagNode, err := c.getObjectTaggingNode(ctx, cnrID, objVersion)
	if err != nil {
		return err
	}

	if tagNode == nil {
		return nil
	}

	return c.removeNode(ctx, cnrID, versionTree, tagNode.ID)
}

func (c *TreeClient) GetBucketTagging(ctx context.Context, cnrID *cid.ID) (map[string]string, error) {
	node, err := c.getSystemNodeWithAllAttributes(ctx, cnrID, systemTree, []string{bucketTaggingFilename})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, layer.ErrNodeNotFound
		}
		return nil, err
	}

	tags := make(map[string]string)

	for key, val := range node.Meta {
		if strings.HasPrefix(key, userDefinedtagPrefix) {
			tags[strings.TrimPrefix(key, userDefinedtagPrefix)] = val
		}
	}

	return tags, nil
}

func (c *TreeClient) PutBucketTagging(ctx context.Context, cnrID *cid.ID, tagSet map[string]string) error {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{bucketTaggingFilename}, []string{})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return fmt.Errorf("couldn't get node: %w", err)
	}

	treeTagSet := make(map[string]string)
	treeTagSet[systemNameKV] = bucketTaggingFilename

	for key, val := range tagSet {
		treeTagSet[userDefinedtagPrefix+key] = val
	}

	if isErrNotFound {
		_, err = c.addNode(ctx, cnrID, systemTree, 0, treeTagSet)
	} else {
		err = c.moveNode(ctx, cnrID, systemTree, node.ID, 0, treeTagSet)
	}

	return err
}

func (c *TreeClient) DeleteBucketTagging(ctx context.Context, cnrID *cid.ID) error {
	node, err := c.getSystemNode(ctx, cnrID, systemTree, []string{bucketTaggingFilename}, nil)
	if err != nil && !errors.Is(err, layer.ErrNodeNotFound) {
		return err
	}

	if node != nil {
		return c.removeNode(ctx, cnrID, systemTree, node.ID)
	}

	return nil
}

func (c *TreeClient) getObjectTaggingNode(ctx context.Context, cnrID *cid.ID, objVersion *data.NodeVersion) (*TreeNode, error) {
	subtree, err := c.getSubTree(ctx, cnrID, versionTree, objVersion.ID, 1)
	if err != nil {
		return nil, err
	}

	var tagNode *TreeNode

	for _, s := range subtree {
		node, err := newTreeNode(s)
		if err != nil {
			return nil, err
		}
		if _, ok := node.Get(isTagKV); ok {
			tagNode = node
			break
		}
	}

	return tagNode, nil
}

func (c *TreeClient) GetVersions(ctx context.Context, cnrID *cid.ID, filepath string) ([]*data.NodeVersion, error) {
	return c.getVersions(ctx, cnrID, versionTree, filepath, false)
}

func (c *TreeClient) GetLatestVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*data.NodeVersion, error) {
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
		var err error
		rootID, err = c.getPrefixNodeID(ctx, cnrID, path[:len(path)-1])
		if err != nil {
			if errors.Is(err, layer.ErrNodeNotFound) {
				return nil, nil
			}
			return nil, err
		}
	}

	subTree, err := c.getSubTree(ctx, cnrID, versionTree, rootID, 1)
	if err != nil {
		return nil, err
	}

	var result []oid.ID
	for _, node := range subTree {
		if node.GetNodeId() != rootID && hasPrefix(node, tailPrefix) {
			latestNodes, err := c.getSubTreeVersions(ctx, cnrID, node.GetNodeId(), true)
			if err != nil {
				return nil, err
			}

			for _, latest := range latestNodes {
				result = append(result, latest.OID)
			}
		}
	}

	return result, nil
}

func (c *TreeClient) getPrefixNodeID(ctx context.Context, cnrID *cid.ID, prefixPath []string) (uint64, error) {
	p := &getNodesParams{
		CnrID:      cnrID,
		TreeID:     versionTree,
		PathAttr:   fileNameKV,
		Path:       prefixPath,
		Meta:       []string{fileNameKV, oidKV},
		LatestOnly: false,
		AllAttrs:   false,
	}
	nodes, err := c.getNodes(ctx, p)
	if err != nil {
		return 0, err
	}

	var intermediateNodes []uint64
	for _, node := range nodes {
		if !hasOID(node) {
			intermediateNodes = append(intermediateNodes, node.GetNodeId())
		}
	}

	if len(intermediateNodes) == 0 {
		return 0, layer.ErrNodeNotFound
	}
	if len(intermediateNodes) > 1 {
		return 0, fmt.Errorf("found more than one intermediate nodes")
	}

	return intermediateNodes[0], nil
}

func hasPrefix(node *tree.GetSubTreeResponse_Body, prefix string) bool {
	for _, kv := range node.GetMeta() {
		if kv.GetKey() == fileNameKV {
			return strings.HasPrefix(string(kv.GetValue()), prefix)
		}
	}

	return false
}

func hasOID(node *tree.GetNodeByPathResponse_Info) bool {
	for _, kv := range node.GetMeta() {
		if kv.GetKey() == oidKV {
			return true
		}
	}

	return false
}

func (c *TreeClient) getSubTreeVersions(ctx context.Context, cnrID *cid.ID, nodeID uint64, latestOnly bool) ([]*data.NodeVersion, error) {
	subTree, err := c.getSubTree(ctx, cnrID, versionTree, nodeID, maxGetSubTreeDepth)
	if err != nil {
		return nil, err
	}

	var emptyOID oid.ID

	versions := make(map[string][]*data.NodeVersion, len(subTree))
	for _, node := range subTree {
		treeNode, err := newTreeNode(node)
		if err != nil || treeNode.ObjID.Equals(emptyOID) { // invalid or empty OID attribute
			continue
		}
		fileName, ok := treeNode.Get(fileNameKV)
		if !ok {
			continue
		}

		key := formLatestNodeKey(node.GetParentId(), fileName)
		versionNodes, ok := versions[key]
		if !ok {
			versionNodes = []*data.NodeVersion{newNodeVersionFromTreeNode(treeNode)}
		} else if !latestOnly {
			versionNodes = append(versionNodes, newNodeVersionFromTreeNode(treeNode))
		} else if versionNodes[0].Timestamp <= treeNode.TimeStamp {
			versionNodes[0] = newNodeVersionFromTreeNode(treeNode)
		}

		versions[key] = versionNodes
	}

	result := make([]*data.NodeVersion, 0, len(versions)) // consider use len(subTree)
	for _, version := range versions {
		if latestOnly && version[0].DeleteMarker != nil {
			continue
		}
		result = append(result, version...)
	}

	return result, nil
}

func formLatestNodeKey(parentID uint64, fileName string) string {
	return strconv.FormatUint(parentID, 10) + fileName
}

func (c *TreeClient) GetAllVersionsByPrefix(ctx context.Context, cnrID *cid.ID, prefix string) ([]*data.NodeVersion, error) {
	var rootID uint64
	path := strings.Split(prefix, separator)
	tailPrefix := path[len(path)-1]

	if len(path) > 1 {
		var err error
		rootID, err = c.getPrefixNodeID(ctx, cnrID, path[:len(path)-1])
		if err != nil {
			if errors.Is(err, layer.ErrNodeNotFound) {
				return nil, nil
			}
			return nil, err
		}
	}

	subTree, err := c.getSubTree(ctx, cnrID, versionTree, rootID, 1)
	if err != nil {
		return nil, err
	}

	var result []*data.NodeVersion
	for _, node := range subTree {
		if node.GetNodeId() != rootID && hasPrefix(node, tailPrefix) {
			versions, err := c.getSubTreeVersions(ctx, cnrID, node.GetNodeId(), false)
			if err != nil {
				return nil, err
			}
			result = append(result, versions...)
		}
	}

	return result, nil
}

func (c *TreeClient) GetSystemVersion(ctx context.Context, cnrID *cid.ID, objectName string) (*data.BaseNodeVersion, error) {
	meta := []string{oidKV}
	path := pathFromName(objectName)

	node, err := c.getLatestVersion(ctx, cnrID, systemTree, systemNameKV, path, meta)
	if err != nil {
		return nil, err
	}
	return &node.BaseNodeVersion, nil
}

func (c *TreeClient) getLatestVersion(ctx context.Context, cnrID *cid.ID, treeID, attrPath string, path, meta []string) (*data.NodeVersion, error) {
	p := &getNodesParams{
		CnrID:      cnrID,
		TreeID:     treeID,
		PathAttr:   attrPath,
		Path:       path,
		Meta:       meta,
		LatestOnly: true,
		AllAttrs:   false,
	}
	nodes, err := c.getNodes(ctx, p)
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

func (c *TreeClient) GetUnversioned(ctx context.Context, cnrID *cid.ID, filepath string) (*data.NodeVersion, error) {
	return c.getUnversioned(ctx, cnrID, versionTree, filepath)
}

func (c *TreeClient) getUnversioned(ctx context.Context, cnrID *cid.ID, treeID, filepath string) (*data.NodeVersion, error) {
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

func (c *TreeClient) AddVersion(ctx context.Context, cnrID *cid.ID, filepath string, version *data.NodeVersion) error {
	return c.addVersion(ctx, cnrID, versionTree, fileNameKV, filepath, version)
}

func (c *TreeClient) AddSystemVersion(ctx context.Context, cnrID *cid.ID, filepath string, version *data.BaseNodeVersion) error {
	newVersion := &data.NodeVersion{
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

func (c *TreeClient) addVersion(ctx context.Context, cnrID *cid.ID, treeID, attrPath, filepath string, version *data.NodeVersion) error {
	path := pathFromName(filepath)
	meta := map[string]string{
		oidKV:    version.OID.String(),
		attrPath: path[len(path)-1],
	}

	if version.DeleteMarker != nil {
		meta[isDeleteMarkerKV] = "true"
		meta[filePathKV] = version.DeleteMarker.FilePath
		meta[ownerKV] = version.DeleteMarker.Owner.EncodeToString()
		meta[createdKV] = strconv.FormatInt(version.DeleteMarker.Created.UTC().UnixMilli(), 10)
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

func (c *TreeClient) getVersions(ctx context.Context, cnrID *cid.ID, treeID, filepath string, onlyUnversioned bool) ([]*data.NodeVersion, error) {
	keysToReturn := []string{oidKV, isUnversionedKV, isDeleteMarkerKV}
	path := pathFromName(filepath)
	p := &getNodesParams{
		CnrID:      cnrID,
		TreeID:     treeID,
		PathAttr:   fileNameKV,
		Path:       path,
		Meta:       keysToReturn,
		LatestOnly: false,
		AllAttrs:   false,
	}
	nodes, err := c.getNodes(ctx, p)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("couldn't get nodes: %w", err)
	}

	result := make([]*data.NodeVersion, 0, len(nodes))
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
	return c.getNode(ctx, cnrID, treeID, systemNameKV, path, meta, false)
}

func (c *TreeClient) getSystemNodeWithAllAttributes(ctx context.Context, cnrID *cid.ID, treeID string, path []string) (*TreeNode, error) {
	return c.getNode(ctx, cnrID, treeID, systemNameKV, path, []string{}, true)
}

func (c *TreeClient) getNode(ctx context.Context, cnrID *cid.ID, treeID, pathAttr string, path, meta []string, allAttrs bool) (*TreeNode, error) {
	p := &getNodesParams{
		CnrID:      cnrID,
		TreeID:     treeID,
		PathAttr:   pathAttr,
		Path:       path,
		Meta:       meta,
		LatestOnly: false,
		AllAttrs:   allAttrs,
	}
	nodes, err := c.getNodes(ctx, p)
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

func (c *TreeClient) getNodes(ctx context.Context, p *getNodesParams) ([]*tree.GetNodeByPathResponse_Info, error) {
	request := &tree.GetNodeByPathRequest{
		Body: &tree.GetNodeByPathRequest_Body{
			ContainerId:   p.CnrID[:],
			TreeId:        p.TreeID,
			Path:          p.Path,
			Attributes:    p.Meta,
			PathAttribute: p.PathAttr,
			LatestOnly:    p.LatestOnly,
			AllAttributes: p.AllAttrs,
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
