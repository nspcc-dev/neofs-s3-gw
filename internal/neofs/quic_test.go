package neofs

import (
	"bytes"
	"io"
	"testing"

	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	protoobject "github.com/nspcc-dev/neofs-sdk-go/proto/object"
	protorefs "github.com/nspcc-dev/neofs-sdk-go/proto/refs"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func encodeQUICServerStream(t *testing.T, hdrObj *protoobject.Object, payload []byte) []byte {
	t.Helper()
	hdrBin, err := proto.Marshal(hdrObj)
	require.NoError(t, err)

	var buf bytes.Buffer
	buf.Write(protowire.AppendTag(nil, quicRespFieldObjectMessage, protowire.BytesType))
	buf.Write(protowire.AppendVarint(nil, uint64(len(hdrBin))))
	buf.Write(hdrBin)
	buf.Write(protowire.AppendTag(nil, quicRespFieldPayloadBytes, protowire.BytesType))
	buf.Write(protowire.AppendVarint(nil, uint64(len(payload))))
	buf.Write(payload)
	return buf.Bytes()
}

func TestParseQUICGetResponse(t *testing.T) {
	objID := oidtest.ID()
	payload := []byte("hello over quic")

	hdrObj := &protoobject.Object{
		ObjectId:  &protorefs.ObjectID{Value: objID[:]},
		Signature: &protorefs.Signature{Key: []byte("k"), Sign: []byte("s"), Scheme: protorefs.SignatureScheme_ECDSA_SHA512},
		Header:    &protoobject.Header{PayloadLength: uint64(len(payload))},
	}

	r := bytes.NewReader(encodeQUICServerStream(t, hdrObj, payload))
	obj, rdr, err := parseQUICGetResponse(r, nil, objID)
	require.NoError(t, err)
	require.NotNil(t, obj)
	require.Equal(t, objID, obj.GetID())
	require.EqualValues(t, len(payload), obj.PayloadSize())

	got, err := io.ReadAll(rdr)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoError(t, rdr.Close())

	t.Run("empty payload", func(t *testing.T) {
		hdrObj.Header = &protoobject.Header{PayloadLength: 0}

		r = bytes.NewReader(encodeQUICServerStream(t, hdrObj, nil))
		obj, rdr, err = parseQUICGetResponse(r, nil, objID)
		require.NoError(t, err)
		require.EqualValues(t, 0, obj.PayloadSize())

		got, err = io.ReadAll(rdr)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("payload size mismatch", func(t *testing.T) {
		hdrObj.Header = &protoobject.Header{PayloadLength: 5}

		r = bytes.NewReader(encodeQUICServerStream(t, hdrObj, []byte("abc")))
		_, _, err = parseQUICGetResponse(r, nil, objID)
		require.ErrorContains(t, err, "payload size mismatch")
	})

	t.Run("short payload stream", func(t *testing.T) {
		hdrObj.Header = &protoobject.Header{PayloadLength: 4}

		full := encodeQUICServerStream(t, hdrObj, []byte("data"))
		truncated := full[:len(full)-2]

		r = bytes.NewReader(truncated)
		_, rdr, err = parseQUICGetResponse(r, nil, objID)
		require.NoError(t, err)
		_, err = io.ReadAll(rdr)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("object id mismatch", func(t *testing.T) {
		wantID := oidtest.ID()
		require.NotEqual(t, objID, wantID)

		hdrObj.Header = &protoobject.Header{PayloadLength: 0}
		r = bytes.NewReader(encodeQUICServerStream(t, hdrObj, nil))
		_, _, err = parseQUICGetResponse(r, nil, wantID)
		require.ErrorContains(t, err, "object id mismatch")
	})
}
