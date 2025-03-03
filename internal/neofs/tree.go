package neofs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

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
	isUnversionedKV     = "IsUnversioned"
	isTagKV             = "IsTag"
	uploadIDKV          = "UploadId"
	partNumberKV        = "Number"
	sizeKV              = "Size"
	etagKV              = "ETag"
	multipartHashKV     = "MultipartHashes"
	homoHashKV          = "HomoHash"
	elementsKV          = "Elements"

	// keys for delete marker nodes.
	isDeleteMarkerKV = "IsDeleteMarker"
	ownerKV          = "Owner"
	ownerPubKeyKV    = "OwnerPubKey"
	createdKV        = "Created"
	serverCreatedKV  = "SrvCreated"

	settingsFileName      = "bucket-settings"
	notifConfFileName     = "bucket-notifications"
	corsFilename          = "bucket-cors"
	bucketTaggingFilename = "bucket-tagging"

	// systemTree -- ID of a tree with system objects
	// i.e. bucket settings with versioning and lock configuration, cors, notifications.
	systemTree = "system"

	separator            = "/"
	userDefinedTagPrefix = "User-Tag-"

	maxGetSubTreeDepth = 0 // means all subTree
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

func newMultipartInfo(node NodeResponse) (*data.MultipartInfo, error) {
	multipartInfo := &data.MultipartInfo{
		Meta: make(map[string]string, len(node.GetMeta())),
	}

	for _, kv := range node.GetMeta() {
		switch kv.GetKey() {
		case uploadIDKV:
			multipartInfo.UploadID = string(kv.GetValue())
		case fileNameKV:
			multipartInfo.Key = string(kv.GetValue())
		case createdKV:
			if utcMilli, err := strconv.ParseInt(string(kv.GetValue()), 10, 64); err == nil {
				multipartInfo.Created = time.UnixMilli(utcMilli)
			}
		case ownerKV:
			_ = multipartInfo.Owner.DecodeString(string(kv.GetValue()))
		case ownerPubKeyKV:
			pk, err := keys.NewPublicKeyFromString(string(kv.GetValue()))
			if err != nil {
				return nil, fmt.Errorf("decode pub key: %w", err)
			}

			multipartInfo.OwnerPubKey = *pk
		default:
			multipartInfo.Meta[kv.GetKey()] = string(kv.GetValue())
		}
	}

	if multipartInfo.UploadID == "" {
		return nil, fmt.Errorf("it's not a multipart node")
	}

	return multipartInfo, nil
}

func newPartInfo(node NodeResponse) (*data.PartInfo, error) {
	var err error
	partInfo := &data.PartInfo{}

	for _, kv := range node.GetMeta() {
		value := string(kv.GetValue())
		switch kv.GetKey() {
		case partNumberKV:
			if partInfo.Number, err = strconv.Atoi(value); err != nil {
				return nil, fmt.Errorf("invalid part number: %w", err)
			}
		case oidKV:
			if err = partInfo.OID.DecodeString(value); err != nil {
				return nil, fmt.Errorf("invalid oid: %w", err)
			}
		case etagKV:
			partInfo.ETag = value
		case sizeKV:
			if partInfo.Size, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, fmt.Errorf("invalid part size: %w", err)
			}
		case createdKV:
			var utcMilli int64
			if utcMilli, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, fmt.Errorf("invalid created timestamp: %w", err)
			}
			partInfo.Created = time.UnixMilli(utcMilli)
		case serverCreatedKV:
			var utcMilli int64
			if utcMilli, err = strconv.ParseInt(value, 10, 64); err != nil {
				return nil, fmt.Errorf("invalid server created timestamp: %w", err)
			}
			partInfo.ServerCreated = time.UnixMilli(utcMilli)
		case multipartHashKV:
			partInfo.MultipartHash = []byte(value)
		case homoHashKV:
			partInfo.HomoHash = []byte(value)
		case elementsKV:
			if value != "" {
				elements := strings.Split(value, ",")
				partInfo.Elements = make([]data.LinkObjectPayload, len(elements))
				for i, e := range elements {
					var element data.LinkObjectPayload
					if err = element.Unmarshal(e); err != nil {
						return nil, fmt.Errorf("invalid element: %w", err)
					}

					partInfo.Elements[i] = element
				}
			}
		}
	}

	if partInfo.Number < 0 {
		return nil, fmt.Errorf("it's not a part node")
	}

	return partInfo, nil
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

func (c *TreeClient) GetBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) (map[string]string, error) {
	node, err := c.getSystemNodeWithAllAttributes(ctx, bktInfo, []string{bucketTaggingFilename})
	if err != nil {
		return nil, err
	}

	tags := make(map[string]string)

	for key, val := range node.Meta {
		if strings.HasPrefix(key, userDefinedTagPrefix) {
			tags[strings.TrimPrefix(key, userDefinedTagPrefix)] = val
		}
	}

	return tags, nil
}

func (c *TreeClient) PutBucketTagging(ctx context.Context, bktInfo *data.BucketInfo, tagSet map[string]string) error {
	node, err := c.getSystemNode(ctx, bktInfo, []string{bucketTaggingFilename}, []string{})
	isErrNotFound := errors.Is(err, layer.ErrNodeNotFound)
	if err != nil && !isErrNotFound {
		return fmt.Errorf("couldn't get node: %w", err)
	}

	treeTagSet := make(map[string]string)
	treeTagSet[fileNameKV] = bucketTaggingFilename

	for key, val := range tagSet {
		treeTagSet[userDefinedTagPrefix+key] = val
	}

	if isErrNotFound {
		_, err = c.addNode(ctx, bktInfo, systemTree, 0, treeTagSet)
	} else {
		err = c.moveNode(ctx, bktInfo, systemTree, node.ID, 0, treeTagSet)
	}

	return err
}

func (c *TreeClient) DeleteBucketTagging(ctx context.Context, bktInfo *data.BucketInfo) error {
	node, err := c.getSystemNode(ctx, bktInfo, []string{bucketTaggingFilename}, nil)
	if err != nil && !errors.Is(err, layer.ErrNodeNotFound) {
		return err
	}

	if node != nil {
		return c.removeNode(ctx, bktInfo, systemTree, node.ID)
	}

	return nil
}

// pathFromName splits name by '/'.
func pathFromName(objectName string) []string {
	return strings.Split(objectName, separator)
}

func (c *TreeClient) determinePrefixNode(ctx context.Context, bktInfo *data.BucketInfo, treeID, prefix string) (uint64, string, error) {
	var rootID uint64
	path := strings.Split(prefix, separator)
	tailPrefix := path[len(path)-1]

	if len(path) > 1 {
		var err error
		rootID, err = c.getPrefixNodeID(ctx, bktInfo, treeID, path[:len(path)-1])
		if err != nil {
			return 0, "", err
		}
	}

	return rootID, tailPrefix, nil
}

func (c *TreeClient) getPrefixNodeID(ctx context.Context, bktInfo *data.BucketInfo, treeID string, prefixPath []string) (uint64, error) {
	p := &getNodesParams{
		BktInfo:    bktInfo,
		TreeID:     treeID,
		Path:       prefixPath,
		LatestOnly: false,
		AllAttrs:   true,
	}
	nodes, err := c.getNodes(ctx, p)
	if err != nil {
		return 0, err
	}

	var intermediateNodes []uint64
	for _, node := range nodes {
		if isIntermediate(node) {
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

func (c *TreeClient) getSubTreeByPrefix(ctx context.Context, bktInfo *data.BucketInfo, treeID, prefix string, latestOnly bool) ([]*tree.GetSubTreeResponse_Body, string, error) {
	rootID, tailPrefix, err := c.determinePrefixNode(ctx, bktInfo, treeID, prefix)
	if err != nil {
		if errors.Is(err, layer.ErrNodeNotFound) {
			return nil, "", nil
		}
		return nil, "", err
	}

	subTree, err := c.getSubTree(ctx, bktInfo, treeID, rootID, 2)
	if err != nil {
		if errors.Is(err, layer.ErrNodeNotFound) {
			return nil, "", nil
		}
		return nil, "", err
	}

	nodesMap := make(map[string][]*tree.GetSubTreeResponse_Body, len(subTree))
	for _, node := range subTree {
		if node.GetNodeId() == rootID {
			continue
		}

		fileName := getFilename(node)
		if !strings.HasPrefix(fileName, tailPrefix) {
			continue
		}

		nodes := nodesMap[fileName]

		// Add all nodes if flag latestOnly is false.
		// Add all intermediate nodes (actually should be exactly one intermediate node with the same name)
		// and only latest leaf (object) nodes. To do this store and replace last leaf (object) node in nodes[0]
		if len(nodes) == 0 {
			nodes = []*tree.GetSubTreeResponse_Body{node}
		} else if !latestOnly || isIntermediate(node) {
			nodes = append(nodes, node)
		} else if isIntermediate(nodes[0]) {
			nodes = append([]*tree.GetSubTreeResponse_Body{node}, nodes...)
		} else if node.GetTimestamp() > nodes[0].GetTimestamp() {
			nodes[0] = node
		}

		nodesMap[fileName] = nodes
	}

	result := make([]*tree.GetSubTreeResponse_Body, 0, len(subTree))
	for _, nodes := range nodesMap {
		result = append(result, nodes...)
	}

	return result, strings.TrimSuffix(prefix, tailPrefix), nil
}

func getFilename(node *tree.GetSubTreeResponse_Body) string {
	for _, kv := range node.GetMeta() {
		if kv.GetKey() == fileNameKV {
			return string(kv.GetValue())
		}
	}

	return ""
}

func isIntermediate(node NodeResponse) bool {
	if len(node.GetMeta()) != 1 {
		return false
	}

	return node.GetMeta()[0].GetKey() == fileNameKV
}

func (c *TreeClient) CreateMultipartUpload(ctx context.Context, bktInfo *data.BucketInfo, info *data.MultipartInfo) (uint64, error) {
	path := pathFromName(info.Key)
	meta := metaFromMultipart(info, path[len(path)-1])
	return c.addNodeByPath(ctx, bktInfo, systemTree, path[:len(path)-1], meta)
}

func (c *TreeClient) GetMultipartUploadsByPrefix(ctx context.Context, bktInfo *data.BucketInfo, prefix string) ([]*data.MultipartInfo, error) {
	subTreeNodes, _, err := c.getSubTreeByPrefix(ctx, bktInfo, systemTree, prefix, false)
	if err != nil {
		return nil, err
	}

	var result []*data.MultipartInfo
	for _, node := range subTreeNodes {
		multipartUploads, err := c.getSubTreeMultipartUploads(ctx, bktInfo, node.GetNodeId())
		if err != nil {
			return nil, err
		}
		result = append(result, multipartUploads...)
	}

	return result, nil
}

func (c *TreeClient) getSubTreeMultipartUploads(ctx context.Context, bktInfo *data.BucketInfo, nodeID uint64) ([]*data.MultipartInfo, error) {
	subTree, err := c.getSubTree(ctx, bktInfo, systemTree, nodeID, maxGetSubTreeDepth)
	if err != nil {
		return nil, err
	}

	result := make([]*data.MultipartInfo, 0, len(subTree))
	for _, node := range subTree {
		multipartInfo, err := newMultipartInfo(node)
		if err != nil { // missed uploadID (it's a part node)
			continue
		}
		result = append(result, multipartInfo)
	}

	return result, nil
}

func (c *TreeClient) GetMultipartUpload(ctx context.Context, bktInfo *data.BucketInfo, objectName, uploadID string) (*data.MultipartInfo, error) {
	path := pathFromName(objectName)
	p := &getNodesParams{
		BktInfo:  bktInfo,
		TreeID:   systemTree,
		Path:     path,
		AllAttrs: true,
	}

	nodes, err := c.getNodes(ctx, p)
	if err != nil {
		return nil, err
	}

	for _, node := range nodes {
		info, err := newMultipartInfo(node)
		if err != nil {
			continue
		}
		if info.UploadID == uploadID {
			return info, nil
		}
	}

	return nil, layer.ErrNodeNotFound
}

func (c *TreeClient) AddPart(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64, info *data.PartInfo) (oldObjIDToDelete oid.ID, err error) {
	parts, err := c.getSubTree(ctx, bktInfo, systemTree, multipartNodeID, 2)
	if err != nil {
		return oid.ID{}, err
	}

	elements := make([]string, len(info.Elements))
	for i, e := range info.Elements {
		elements[i] = e.Marshal()
	}

	meta := map[string]string{
		partNumberKV:    strconv.Itoa(info.Number),
		oidKV:           info.OID.EncodeToString(),
		sizeKV:          strconv.FormatInt(info.Size, 10),
		createdKV:       strconv.FormatInt(info.Created.UTC().UnixMilli(), 10),
		serverCreatedKV: strconv.FormatInt(time.Now().UTC().UnixMilli(), 10),
		etagKV:          info.ETag,
		multipartHashKV: string(info.MultipartHash),
		homoHashKV:      string(info.HomoHash),
		elementsKV:      strings.Join(elements, ","),
	}

	var foundPartID uint64
	for _, part := range parts {
		if part.GetNodeId() == multipartNodeID {
			continue
		}
		partInfo, err := newPartInfo(part)
		if err != nil {
			continue
		}
		if partInfo.Number == info.Number {
			foundPartID = part.GetNodeId()
			oldObjIDToDelete = partInfo.OID
			break
		}
	}

	if foundPartID != multipartNodeID {
		if _, err = c.addNode(ctx, bktInfo, systemTree, multipartNodeID, meta); err != nil {
			return oid.ID{}, err
		}
		return oid.ID{}, layer.ErrNoNodeToRemove
	}

	return oldObjIDToDelete, c.moveNode(ctx, bktInfo, systemTree, foundPartID, multipartNodeID, meta)
}

func (c *TreeClient) GetParts(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64) ([]*data.PartInfo, error) {
	parts, err := c.getSubTree(ctx, bktInfo, systemTree, multipartNodeID, 2)
	if err != nil {
		return nil, err
	}

	result := make([]*data.PartInfo, 0, len(parts))
	for _, part := range parts {
		if part.GetNodeId() == multipartNodeID {
			continue
		}
		partInfo, err := newPartInfo(part)
		if err != nil {
			continue
		}
		result = append(result, partInfo)
	}

	return result, nil
}

func (c *TreeClient) GetPartByNumber(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64, number int) (*data.PartInfo, error) {
	parts, err := c.GetParts(ctx, bktInfo, multipartNodeID)
	if err != nil {
		return nil, fmt.Errorf("get parts: %w", err)
	}

	if len(parts) == 0 {
		return nil, layer.ErrPartListIsEmpty
	}

	// Sort parts by part number, then by server creation time to make actual last uploaded parts with the same number.
	slices.SortFunc(parts, data.SortPartInfo)

	var pi *data.PartInfo
	for _, part := range parts {
		if part.Number != number {
			continue
		}

		if pi == nil || pi.ServerCreated.Before(part.ServerCreated) {
			pi = part
		}
	}

	return pi, nil
}

// GetPartsAfter returns parts uploaded after partID. These parts are sorted and filtered by creation time.
// It means, if any upload had a re-uploaded data (few part versions), the list contains only the latest version of the upload.
func (c *TreeClient) GetPartsAfter(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64, partID int) ([]*data.PartInfo, error) {
	parts, err := c.getSubTree(ctx, bktInfo, systemTree, multipartNodeID, 2)
	if err != nil {
		return nil, err
	}

	if len(parts) == 0 {
		return nil, layer.ErrPartListIsEmpty
	}

	mp := make(map[int]*data.PartInfo)
	for _, part := range parts {
		if part.GetNodeId() == multipartNodeID {
			continue
		}

		partInfo, err := newPartInfo(part)
		if err != nil {
			continue
		}

		if partInfo.Number <= partID {
			continue
		}

		mapped, ok := mp[partInfo.Number]
		if !ok {
			mp[partInfo.Number] = partInfo
			continue
		}

		if mapped.ServerCreated.After(partInfo.ServerCreated) {
			continue
		}

		mp[partInfo.Number] = partInfo
	}

	if len(mp) == 0 {
		return nil, layer.ErrPartListIsEmpty
	}

	result := make([]*data.PartInfo, 0, len(mp))
	for _, p := range mp {
		result = append(result, p)
	}

	// Sort parts by part number, then by server creation time to make actual last uploaded parts with the same number.
	slices.SortFunc(result, data.SortPartInfo)

	return result, nil
}

func (c *TreeClient) DeleteMultipartUpload(ctx context.Context, bktInfo *data.BucketInfo, multipartNodeID uint64) error {
	return c.removeNode(ctx, bktInfo, systemTree, multipartNodeID)
}

func (c *TreeClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func (c *TreeClient) getSubTree(ctx context.Context, bktInfo *data.BucketInfo, treeID string, rootID uint64, depth uint32) ([]*tree.GetSubTreeResponse_Body, error) {
	request := &tree.GetSubTreeRequest{
		Body: &tree.GetSubTreeRequest_Body{
			ContainerId: bktInfo.CID[:],
			TreeId:      treeID,
			RootId:      rootID,
			Depth:       depth,
			BearerToken: getBearer(ctx, bktInfo),
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
		return nil, handleError("failed to get sub tree client", err)
	}

	var subtree []*tree.GetSubTreeResponse_Body
	for {
		resp, err := cli.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, handleError("failed to get sub tree", err)
		}
		subtree = append(subtree, resp.Body)
	}

	return subtree, nil
}

func metaFromSettings(settings *data.BucketSettings) map[string]string {
	results := make(map[string]string, 3)

	results[fileNameKV] = settingsFileName
	results[versioningKV] = settings.Versioning
	results[lockConfigurationKV] = encodeLockConfiguration(settings.LockConfiguration)

	return results
}

func metaFromMultipart(info *data.MultipartInfo, fileName string) map[string]string {
	info.Meta[fileNameKV] = fileName
	info.Meta[uploadIDKV] = info.UploadID
	info.Meta[ownerPubKeyKV] = hex.EncodeToString(info.OwnerPubKey.Bytes())
	info.Meta[ownerKV] = info.Owner.EncodeToString()
	info.Meta[createdKV] = strconv.FormatInt(info.Created.UTC().UnixMilli(), 10)

	return info.Meta
}

func (c *TreeClient) getSystemNode(ctx context.Context, bktInfo *data.BucketInfo, path, meta []string) (*TreeNode, error) {
	return c.getNode(ctx, bktInfo, systemTree, path, meta, false)
}

func (c *TreeClient) getSystemNodeWithAllAttributes(ctx context.Context, bktInfo *data.BucketInfo, path []string) (*TreeNode, error) {
	return c.getNode(ctx, bktInfo, systemTree, path, []string{}, true)
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

func (c *TreeClient) addNodeByPath(ctx context.Context, bktInfo *data.BucketInfo, treeID string, path []string, meta map[string]string) (uint64, error) {
	request := &tree.AddByPathRequest{
		Body: &tree.AddByPathRequest_Body{
			ContainerId:   bktInfo.CID[:],
			TreeId:        treeID,
			Path:          path,
			Meta:          metaToKV(meta),
			PathAttribute: fileNameKV,
			BearerToken:   getBearer(ctx, bktInfo),
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

	resp, err := c.service.AddByPath(ctx, request)
	if err != nil {
		return 0, handleError("failed to add node by path", err)
	}

	body := resp.GetBody()
	if body == nil {
		return 0, errors.New("nil body in tree service response")
	} else if len(body.Nodes) == 0 {
		return 0, errors.New("empty list of added nodes in tree service response")
	}

	// The first node is the leaf that we add, according to tree service docs.
	return body.Nodes[0], nil
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
