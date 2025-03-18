package neofs

import (
	"context"
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
	oidKV      = "OID"
	fileNameKV = "FileName"
	sizeKV     = "Size"

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

func (c *TreeClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
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

func metaToKV(meta map[string]string) []*tree.KeyValue {
	result := make([]*tree.KeyValue, 0, len(meta))

	for key, value := range meta {
		result = append(result, &tree.KeyValue{Key: key, Value: []byte(value)})
	}

	return result
}
