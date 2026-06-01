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

func encodeServerStream(t *testing.T, hdrObj *protoobject.Object, payload []byte) []byte {
	t.Helper()
	hdrBin, err := proto.Marshal(hdrObj)
	require.NoError(t, err)

	var buf bytes.Buffer
	buf.Write(protowire.AppendTag(nil, httpRespFieldObjectMessage, protowire.BytesType))
	buf.Write(protowire.AppendVarint(nil, uint64(len(hdrBin))))
	buf.Write(hdrBin)
	buf.Write(protowire.AppendTag(nil, httpRespFieldPayloadBytes, protowire.BytesType))
	buf.Write(protowire.AppendVarint(nil, uint64(len(payload))))
	buf.Write(payload)
	return buf.Bytes()
}

func TestParseHTTPGetResponse(t *testing.T) {
	objID := oidtest.ID()
	payload := []byte("hello over plain http")

	hdrObj := &protoobject.Object{
		ObjectId:  &protorefs.ObjectID{Value: objID[:]},
		Signature: &protorefs.Signature{Key: []byte("k"), Sign: []byte("s"), Scheme: protorefs.SignatureScheme_ECDSA_SHA512},
		Header:    &protoobject.Header{PayloadLength: uint64(len(payload))},
	}

	body := io.NopCloser(bytes.NewReader(encodeServerStream(t, hdrObj, payload)))
	obj, rdr, err := parseHTTPGetResponse(body, objID)
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

		body = io.NopCloser(bytes.NewReader(encodeServerStream(t, hdrObj, nil)))
		obj, rdr, err = parseHTTPGetResponse(body, objID)
		require.NoError(t, err)
		require.EqualValues(t, 0, obj.PayloadSize())

		got, err = io.ReadAll(rdr)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("payload size mismatch", func(t *testing.T) {
		hdrObj.Header = &protoobject.Header{PayloadLength: 5}

		body = io.NopCloser(bytes.NewReader(encodeServerStream(t, hdrObj, []byte("abc"))))
		_, _, err = parseHTTPGetResponse(body, objID)
		require.ErrorContains(t, err, "payload size mismatch")
	})

	t.Run("short payload stream", func(t *testing.T) {
		hdrObj.Header = &protoobject.Header{PayloadLength: 4}

		full := encodeServerStream(t, hdrObj, []byte("data"))
		truncated := full[:len(full)-2]

		body = io.NopCloser(bytes.NewReader(truncated))
		_, rdr, err = parseHTTPGetResponse(body, objID)
		require.NoError(t, err)
		_, err = io.ReadAll(rdr)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("object id mismatch", func(t *testing.T) {
		wantID := oidtest.ID()
		require.NotEqual(t, objID, wantID)

		hdrObj.Header = &protoobject.Header{PayloadLength: 0}
		body = io.NopCloser(bytes.NewReader(encodeServerStream(t, hdrObj, nil)))
		_, _, err = parseHTTPGetResponse(body, wantID)
		require.ErrorContains(t, err, "object id mismatch")
	})
}
