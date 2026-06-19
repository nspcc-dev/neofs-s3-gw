package neofs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	protoobject "github.com/nspcc-dev/neofs-sdk-go/proto/object"
	protosession "github.com/nspcc-dev/neofs-sdk-go/proto/session"
	protostatus "github.com/nspcc-dev/neofs-sdk-go/proto/status"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	httpRespFieldObjectMessage protowire.Number = 3
	httpRespFieldPayloadBytes  protowire.Number = 4
	httpGetPath                                 = "/get"
	defaultRequestTTL                           = 2
)

type httpClient struct {
	client *http.Client
}

func newHTTPClient() *httpClient {
	return &httpClient{
		client: &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
			},
		},
	}
}

func (t *httpClient) get(ctx context.Context, endpoint string, req *protoobject.GetRequest, requestedID oid.ID) (*object.Object, *httpPayloadReader, error) {
	body, err := proto.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal get request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+httpGetPath, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("build http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/protobuf")
	httpReq.ContentLength = int64(len(body))

	httpResp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("send get request: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		err := decodeHTTPStatusError(httpResp)
		httpResp.Body.Close()
		return nil, nil, err
	}

	obj, payload, err := parseHTTPGetResponse(httpResp.Body, requestedID)
	if err != nil {
		httpResp.Body.Close()
		return nil, nil, err
	}
	return obj, payload, nil
}

func decodeHTTPStatusError(resp *http.Response) error {
	const maxStatusBody = 16 * 1024
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/protobuf") {
		return fmt.Errorf("unexpected http status %s", resp.Status)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody))
	if readErr != nil || len(body) == 0 {
		return fmt.Errorf("unexpected http status %s", resp.Status)
	}

	var st protostatus.Status
	if proto.Unmarshal(body, &st) != nil {
		return fmt.Errorf("unexpected http status %s", resp.Status)
	}
	if apiErr := apistatus.ToError(&st); apiErr != nil {
		return apiErr
	}
	return fmt.Errorf("unexpected http status %s", resp.Status)
}

func parseHTTPGetResponse(body io.ReadCloser, requestedID oid.ID) (*object.Object, *httpPayloadReader, error) {
	br := bufio.NewReader(body)

	obj, err := readObjectField(br, requestedID)
	if err != nil {
		return nil, nil, fmt.Errorf("read object header field: %w", err)
	}

	payloadLen, err := readPayloadFieldPrefix(br)
	if err != nil {
		return nil, nil, fmt.Errorf("read payload field prefix: %w", err)
	}
	if payloadLen != obj.PayloadSize() {
		return nil, nil, fmt.Errorf("payload size mismatch: header=%d, stream=%d", obj.PayloadSize(), payloadLen)
	}

	return obj, &httpPayloadReader{
		body:      body,
		rdr:       br,
		remaining: payloadLen,
	}, nil
}

func readObjectField(br *bufio.Reader, requestedID oid.ID) (*object.Object, error) {
	num, typ, err := readWireTag(br)
	if err != nil {
		return nil, err
	}
	if num != httpRespFieldObjectMessage || typ != protowire.BytesType {
		return nil, fmt.Errorf("unexpected first field: num=%d type=%d", num, typ)
	}
	hdrLen, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, fmt.Errorf("read header length: %w", err)
	}
	headerBytes := make([]byte, hdrLen)
	if _, err = io.ReadFull(br, headerBytes); err != nil {
		return nil, fmt.Errorf("read header bytes: %w", err)
	}
	var protoObj protoobject.Object
	if err = proto.Unmarshal(headerBytes, &protoObj); err != nil {
		return nil, fmt.Errorf("unmarshal object: %w", err)
	}
	var obj object.Object
	if err = obj.FromProtoMessage(&protoObj); err != nil {
		return nil, fmt.Errorf("decode object: %w", err)
	}
	if !requestedID.IsZero() {
		if got := obj.GetID(); !got.IsZero() && got != requestedID {
			return nil, fmt.Errorf("response object id mismatch: got %s, want %s", got, requestedID)
		}
	}
	return &obj, nil
}

func readPayloadFieldPrefix(br *bufio.Reader) (uint64, error) {
	num, typ, err := readWireTag(br)
	if err != nil {
		return 0, err
	}
	if num != httpRespFieldPayloadBytes || typ != protowire.BytesType {
		return 0, fmt.Errorf("unexpected payload field: num=%d type=%d", num, typ)
	}
	pldLen, err := binary.ReadUvarint(br)
	if err != nil {
		return 0, fmt.Errorf("read payload length: %w", err)
	}
	return pldLen, nil
}

func readWireTag(br *bufio.Reader) (protowire.Number, protowire.Type, error) {
	v, err := binary.ReadUvarint(br)
	if err != nil {
		return 0, 0, fmt.Errorf("read wire tag: %w", err)
	}
	num, typ := protowire.DecodeTag(v)
	if num < 0 {
		return 0, 0, errors.New("invalid wire tag")
	}
	return num, typ, nil
}

type httpPayloadReader struct {
	body      io.ReadCloser
	rdr       *bufio.Reader
	remaining uint64
	closed    bool
}

func (r *httpPayloadReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if uint64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.rdr.Read(p)
	if n > 0 {
		r.remaining -= uint64(n)
	}
	if errors.Is(err, io.EOF) && r.remaining != 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (r *httpPayloadReader) WriteTo(w io.Writer) (int64, error) {
	if r.remaining == 0 {
		return 0, nil
	}
	n, err := io.CopyN(w, r.rdr, int64(r.remaining))
	r.remaining -= uint64(n)
	if errors.Is(err, io.EOF) && r.remaining != 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (r *httpPayloadReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.body.Close()
}

func (x *NeoFS) httpEndpoint() (string, error) {
	cl, err := x.pool.RawClient()
	if err != nil {
		return "", fmt.Errorf("pick storage node: %w", err)
	}
	conn := cl.Conn()
	if conn == nil {
		return "", errors.New("nil grpc connection in raw client")
	}
	target := conn.Target()
	// strip an optional gRPC resolver scheme prefix like "passthrough:///".
	if idx := strings.Index(target, "://"); idx >= 0 {
		target = strings.TrimLeft(target[idx+3:], "/")
	}
	return "http://" + target, nil
}

func (x *NeoFS) getObjectHTTP(ctx context.Context, prm layer.GetObject) (*layer.ObjectPart, error) {
	endpoint, err := x.httpEndpoint()
	if err != nil {
		return nil, err
	}
	req, err := newGetRequest(x.signer(ctx), prm.Container, prm.Object, prm.PrmAuth)
	if err != nil {
		return nil, fmt.Errorf("build get request: %w", err)
	}
	obj, payload, err := x.httpCli.get(ctx, endpoint, req, prm.Object)
	if err != nil {
		return nil, err
	}
	return &layer.ObjectPart{Head: obj, Payload: payload}, nil
}

func newGetRequest(signer user.Signer, cnr cid.ID, obj oid.ID, auth layer.PrmAuth) (*protoobject.GetRequest, error) {
	req := &protoobject.GetRequest{
		Body: &protoobject.GetRequest_Body{
			Address: oid.NewAddress(cnr, obj).ProtoMessage(),
		},
		MetaHeader: newRequestMetaHeader(auth),
	}
	vh, err := neofscrypto.SignRequestWithBuffer[*protoobject.GetRequest_Body](signer, req, nil)
	if err != nil {
		return nil, fmt.Errorf("sign get request: %w", err)
	}
	req.VerifyHeader = vh
	return req, nil
}

func newRequestMetaHeader(auth layer.PrmAuth) *protosession.RequestMetaHeader {
	meta := &protosession.RequestMetaHeader{
		Version: version.Current().ProtoMessage(),
		Ttl:     defaultRequestTTL,
	}
	if auth.SessionTokenV2 != nil {
		meta.SessionTokenV2 = auth.SessionTokenV2.ProtoMessage()
	}
	return meta
}
