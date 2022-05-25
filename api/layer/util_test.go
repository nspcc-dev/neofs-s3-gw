package layer

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
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

func newTestObject(id oid.ID, bkt *data.BucketInfo, name string) *object.Object {
	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(name)

	created := object.NewAttribute()
	created.SetKey(object.AttributeTimestamp)
	created.SetValue(strconv.FormatInt(defaultTestCreated.Unix(), 10))

	contentType := object.NewAttribute()
	contentType.SetKey(object.AttributeContentType)
	contentType.SetValue(defaultTestContentType)

	obj := object.New()
	obj.SetID(id)
	obj.SetOwnerID(&bkt.Owner)
	obj.SetContainerID(bkt.CID)
	obj.SetPayload(defaultTestPayload)
	obj.SetAttributes(*filename, *created, *contentType)
	obj.SetPayloadSize(uint64(defaultTestPayloadLength))

	return obj
}

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

func Test_objectInfoFromMeta(t *testing.T) {
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
		object    *object.Object
		delimiter string
	}{
		{
			name:   "small.jpg",
			result: newTestInfo(id, bkt, "small.jpg", false),
			object: newTestObject(id, bkt, "small.jpg"),
		},
		{
			name:   "small.jpg not matched prefix",
			prefix: "big",
			result: nil,
			object: newTestObject(id, bkt, "small.jpg"),
		},
		{
			name:      "small.jpg delimiter",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "small.jpg", false),
			object:    newTestObject(id, bkt, "small.jpg"),
		},
		{
			name:   "test/small.jpg",
			result: newTestInfo(id, bkt, "test/small.jpg", false),
			object: newTestObject(id, bkt, "test/small.jpg"),
		},
		{
			name:      "test/small.jpg with prefix and delimiter",
			prefix:    "test/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "test/small.jpg", false),
			object:    newTestObject(id, bkt, "test/small.jpg"),
		},
		{
			name:   "a/b/small.jpg",
			prefix: "a",
			result: newTestInfo(id, bkt, "a/b/small.jpg", false),
			object: newTestObject(id, bkt, "a/b/small.jpg"),
		},
		{
			name:      "a/b/small.jpg",
			prefix:    "a/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/", true),
			object:    newTestObject(id, bkt, "a/b/small.jpg"),
		},
		{
			name:      "a/b/c/small.jpg",
			prefix:    "a/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/", true),
			object:    newTestObject(id, bkt, "a/b/c/small.jpg"),
		},
		{
			name:      "a/b/c/small.jpg",
			prefix:    "a/b/c/s",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/c/small.jpg", false),
			object:    newTestObject(id, bkt, "a/b/c/small.jpg"),
		},
		{
			name:      "a/b/c/big.jpg",
			prefix:    "a/b/",
			delimiter: "/",
			result:    newTestInfo(id, bkt, "a/b/c/", true),
			object:    newTestObject(id, bkt, "a/b/c/big.jpg"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := objectInfoFromMeta(bkt, tc.object, tc.prefix, tc.delimiter)
			require.Equal(t, tc.result, info)
		})
	}
}
