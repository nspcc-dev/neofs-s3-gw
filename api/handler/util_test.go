package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
)

var (
	defaultTestCreated       = time.Now()
	defaultTestPayload       = []byte("test object payload")
	defaultTestPayloadLength = int64(len(defaultTestPayload))
	defaultTestContentType   = http.DetectContentType(defaultTestPayload)
)

func newTestInfo(obj oid.ID, bkt *data.BucketInfo, name string, isDir bool) *data.ObjectInfo {
	var hashSum checksum.Checksum
	info := &data.ObjectInfo{
		ID:          obj,
		Name:        name,
		Bucket:      bkt.Name,
		CID:         bkt.CID,
		Size:        defaultTestPayloadLength,
		ContentType: defaultTestContentType,
		Created:     time.Unix(defaultTestCreated.Unix(), 0),
		Owner:       bkt.Owner,
		Headers:     make(map[string]string),
		HashSum:     hex.EncodeToString(hashSum.Value()),
	}

	if isDir {
		info.IsDir = true
		info.Size = 0
		info.ContentType = ""
		info.Headers = nil
	}

	return info
}

func newTestNodeVersion(id oid.ID, name string) *data.NodeVersion {
	return &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			OID:      id,
			FilePath: name,
		},
	}
}

func TestTryDirectory(t *testing.T) {
	var uid user.ID
	var id oid.ID
	var containerID cid.ID

	bkt := &data.BucketInfo{
		Name:    "test-container",
		CID:     containerID,
		Owner:   uid,
		Created: time.Now(),
	}

	cases := []struct {
		name      string
		prefix    string
		result    *data.ObjectInfo
		node      *data.NodeVersion
		delimiter string
	}{
		{
			name:   "small.jpg",
			result: nil,
			node:   newTestNodeVersion(id, "small.jpg"),
		},
		{
			name:   "small.jpg not matched prefix",
			prefix: "big",
			result: nil,
			node:   newTestNodeVersion(id, "small.jpg"),
		},
		{
			name:      "small.jpg delimiter",
			delimiter: "/",
			result:    nil,
			node:      newTestNodeVersion(id, "small.jpg"),
		},
		{
			name:   "test/small.jpg",
			result: nil,
			node:   newTestNodeVersion(id, "test/small.jpg"),
		},
		{
			name:      "test/small.jpg with prefix and delimiter",
			prefix:    "test/",
			delimiter: "/",
			result:    nil,
			node:      newTestNodeVersion(id, "test/small.jpg"),
		},
		{
			name:   "a/b/small.jpg",
			prefix: "a",
			result: nil,
			node:   newTestNodeVersion(id, "a/b/small.jpg"),
		},
		{
			name:      "a/b/small.jpg",
			prefix:    "a/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/", true),
			node:      newTestNodeVersion(id, "a/b/small.jpg"),
		},
		{
			name:      "a/b/c/small.jpg",
			prefix:    "a/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/", true),
			node:      newTestNodeVersion(id, "a/b/c/small.jpg"),
		},
		{
			name:      "a/b/c/small.jpg",
			prefix:    "a/b/c/s",
			delimiter: "/",
			result:    nil,
			node:      newTestNodeVersion(id, "a/b/c/small.jpg"),
		},
		{
			name:      "a/b/c/big.jpg",
			prefix:    "a/b/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/c/", true),
			node:      newTestNodeVersion(id, "a/b/c/big.jpg"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := tryDirectory(bkt, tc.node, tc.prefix, tc.delimiter)
			if tc.result != nil {
				tc.result.Created = time.Time{}
				tc.result.Owner = user.ID{}
			}

			require.Equal(t, tc.result, info)
		})
	}
}

func TestWrapReader(t *testing.T) {
	src := make([]byte, 1024*1024+1)
	_, err := rand.Read(src)
	require.NoError(t, err)
	h := sha256.Sum256(src)

	streamHash := sha256.New()
	reader := bytes.NewReader(src)
	wrappedReader := wrapReader(reader, 64*1024, func(buf []byte) {
		streamHash.Write(buf)
	})

	dst, err := io.ReadAll(wrappedReader)
	require.NoError(t, err)
	require.Equal(t, src, dst)
	require.Equal(t, h[:], streamHash.Sum(nil))
}
