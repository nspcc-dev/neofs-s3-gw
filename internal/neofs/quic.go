package neofs

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	quicALPN = "neofs-get-quic"

	quicStatusOK    byte = 0
	quicStatusError byte = 1

	quicRespFieldObjectMessage protowire.Number = 3
	quicRespFieldPayloadBytes  protowire.Number = 4

	quicMaxStatusBody = 16 * 1024
)

type quicClient struct {
	tlsConf  *tls.Config
	quicConf *quic.Config

	mtx   sync.Mutex
	conns map[string]*quic.Conn // keyed by host:port
}

func newQUICClient() *quicClient {
	return &quicClient{
		tlsConf: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // prototype: ephemeral self-signed server cert
			NextProtos:         []string{quicALPN},
			MinVersion:         tls.VersionTLS13,
		},
		quicConf: &quic.Config{
			MaxIncomingStreams: 1 << 16,
			MaxIdleTimeout:     5 * time.Minute,
			KeepAlivePeriod:    30 * time.Second,
		},
		conns: make(map[string]*quic.Conn),
	}
}

func (t *quicClient) conn(ctx context.Context, addr string) (*quic.Conn, error) {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if c := t.conns[addr]; c != nil && c.Context().Err() == nil {
		return c, nil
	}

	c, err := quic.DialAddr(ctx, addr, t.tlsConf, t.quicConf)
	if err != nil {
		return nil, fmt.Errorf("dial QUIC %q: %w", addr, err)
	}
	t.conns[addr] = c
	return c, nil
}

func (t *quicClient) get(ctx context.Context, addr string, req *protoobject.GetRequest, requestedID oid.ID) (*object.Object, *quicPayloadReader, error) {
	body, err := proto.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal get request: %w", err)
	}

	conn, err := t.conn(ctx, addr)
	if err != nil {
		return nil, nil, err
	}

	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("open QUIC stream: %w", err)
	}

	if _, err = st.Write(body); err != nil {
		st.CancelRead(0)
		return nil, nil, fmt.Errorf("write get request: %w", err)
	}
	if err = st.Close(); err != nil { // FIN the send side
		st.CancelRead(0)
		return nil, nil, fmt.Errorf("finish get request: %w", err)
	}

	var sb [1]byte
	if _, err = io.ReadFull(st, sb[:]); err != nil {
		st.CancelRead(0)
		return nil, nil, fmt.Errorf("read response status: %w", err)
	}
	if sb[0] != quicStatusOK {
		err = decodeQUICStatusError(st)
		st.CancelRead(0)
		return nil, nil, err
	}

	obj, payload, err := parseQUICGetResponse(st, func() { st.CancelRead(0) }, requestedID)
	if err != nil {
		st.CancelRead(0)
		return nil, nil, err
	}
	return obj, payload, nil
}

func decodeQUICStatusError(st *quic.Stream) error {
	body, readErr := io.ReadAll(io.LimitReader(st, quicMaxStatusBody))
	if readErr != nil || len(body) == 0 {
		return errors.New("storage node returned an error status")
	}
	var status protostatus.Status
	if proto.Unmarshal(body, &status) != nil {
		return errors.New("storage node returned an error status")
	}
	if apiErr := apistatus.ToError(&status); apiErr != nil {
		return apiErr
	}
	return errors.New("storage node returned an error status")
}

func parseQUICGetResponse(r io.Reader, onClose func(), requestedID oid.ID) (*object.Object, *quicPayloadReader, error) {
	br := bufio.NewReader(r)

	obj, err := readQUICObjectField(br, requestedID)
	if err != nil {
		return nil, nil, fmt.Errorf("read object header field: %w", err)
	}

	payloadLen, err := readQUICPayloadFieldPrefix(br)
	if err != nil {
		return nil, nil, fmt.Errorf("read payload field prefix: %w", err)
	}
	if payloadLen != obj.PayloadSize() {
		return nil, nil, fmt.Errorf("payload size mismatch: header=%d, stream=%d", obj.PayloadSize(), payloadLen)
	}

	return obj, &quicPayloadReader{
		onClose:   onClose,
		rdr:       br,
		remaining: payloadLen,
	}, nil
}

func readQUICObjectField(br *bufio.Reader, requestedID oid.ID) (*object.Object, error) {
	num, typ, err := readQUICWireTag(br)
	if err != nil {
		return nil, err
	}
	if num != quicRespFieldObjectMessage || typ != protowire.BytesType {
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

func readQUICPayloadFieldPrefix(br *bufio.Reader) (uint64, error) {
	num, typ, err := readQUICWireTag(br)
	if err != nil {
		return 0, err
	}
	if num != quicRespFieldPayloadBytes || typ != protowire.BytesType {
		return 0, fmt.Errorf("unexpected payload field: num=%d type=%d", num, typ)
	}
	pldLen, err := binary.ReadUvarint(br)
	if err != nil {
		return 0, fmt.Errorf("read payload length: %w", err)
	}
	return pldLen, nil
}

func readQUICWireTag(br *bufio.Reader) (protowire.Number, protowire.Type, error) {
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

type quicPayloadReader struct {
	onClose   func()
	rdr       *bufio.Reader
	remaining uint64
	closed    bool
}

func (r *quicPayloadReader) Read(p []byte) (int, error) {
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

func (r *quicPayloadReader) WriteTo(w io.Writer) (int64, error) {
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

func (r *quicPayloadReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.onClose != nil {
		r.onClose()
	}
	return nil
}

func (x *NeoFS) quicEndpoint() (string, error) {
	cl, err := x.pool.RawClient()
	if err != nil {
		return "", fmt.Errorf("pick storage node: %w", err)
	}
	conn := cl.Conn()
	if conn == nil {
		return "", errors.New("nil grpc connection in raw client")
	}
	target := conn.Target()
	if idx := strings.Index(target, "://"); idx >= 0 {
		target = strings.TrimLeft(target[idx+3:], "/")
	}
	return target, nil
}

func (x *NeoFS) getObjectQUIC(ctx context.Context, prm layer.GetObject) (*layer.ObjectPart, error) {
	endpoint, err := x.quicEndpoint()
	if err != nil {
		return nil, err
	}
	req, err := newGetRequest(x.signer(ctx), prm.Container, prm.Object, prm.PrmAuth)
	if err != nil {
		return nil, fmt.Errorf("build get request: %w", err)
	}
	obj, payload, err := x.quicCli.get(ctx, endpoint, req, prm.Object)
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
	const defaultRequestTTL = 2
	meta := &protosession.RequestMetaHeader{
		Version: version.Current().ProtoMessage(),
		Ttl:     defaultRequestTTL,
	}
	if auth.SessionTokenV2 != nil {
		meta.SessionTokenV2 = auth.SessionTokenV2.ProtoMessage()
	}
	if auth.BearerToken != nil {
		meta.BearerToken = auth.BearerToken.ProtoMessage()
	}
	return meta
}
