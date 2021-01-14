package layer

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/stretchr/testify/require"
)

var (
	defaultTestCreated       = time.Now()
	defaultTestPayload       = []byte("test object payload")
	defaultTestPayloadLength = int64(len(defaultTestPayload))
	defaultTestContentType   = http.DetectContentType(defaultTestPayload)
)

func newTestObject(oid *object.ID, bkt *BucketInfo, name string) *object.Object {
	filename := object.NewAttribute()
	filename.SetKey(object.AttributeFileName)
	filename.SetValue(name)

	created := object.NewAttribute()
	created.SetKey(object.AttributeTimestamp)
	created.SetValue(strconv.FormatInt(defaultTestCreated.Unix(), 10))

	raw := object.NewRaw()
	raw.SetID(oid)
	raw.SetOwnerID(bkt.Owner)
	raw.SetContainerID(bkt.CID)
	raw.SetPayload(defaultTestPayload)
	raw.SetAttributes(filename, created)
	raw.SetPayloadSize(uint64(defaultTestPayloadLength))

	return raw.Object()
}

func newTestInfo(oid *object.ID, bkt *BucketInfo, name, prefix string) *ObjectInfo {
	info := &ObjectInfo{
		id:          oid,
		Name:        name,
		Bucket:      bkt.Name,
		Size:        defaultTestPayloadLength,
		ContentType: defaultTestContentType,
		Created:     time.Unix(defaultTestCreated.Unix(), 0),
		Owner:       bkt.Owner,
		Headers:     make(map[string]string),
	}

	if prefix == rootSeparator {
		return info
	}

	_, dirname := testNameFromObjectName(name)
	if ln := len(prefix); ln > 0 && prefix[ln-1:] != PathSeparator {
		prefix += PathSeparator
	}

	tail := strings.TrimPrefix(dirname, prefix)
	if index := strings.Index(tail, PathSeparator); index >= 0 {
		info.isDir = true

		info.Size = 0
		info.ContentType = ""
		info.Name = tail[:index+1]
		info.Headers = nil
	}

	return info
}

func testNameFromObjectName(name string) (string, string) {
	ind := strings.LastIndex(name, PathSeparator)

	return name[ind+1:], name[:ind+1]
}

func Test_objectInfoFromMeta(t *testing.T) {
	uid := owner.NewID()
	oid := object.NewID()
	cid := container.NewID()

	bkt := &BucketInfo{
		Name:    "test-container",
		CID:     cid,
		Owner:   uid,
		Created: time.Now(),
	}

	cases := []struct {
		name   string
		prefix string
		result *ObjectInfo
		object *object.Object

		infoName string
	}{
		{
			name:     "test.jpg",
			prefix:   "",
			infoName: "test.jpg",
			result:   newTestInfo(oid, bkt, "test.jpg", ""),
			object:   newTestObject(oid, bkt, "test.jpg"),
		},

		{
			name:     "test/small.jpg",
			prefix:   "",
			infoName: "test/",
			result:   newTestInfo(oid, bkt, "test/small.jpg", ""),
			object:   newTestObject(oid, bkt, "test/small.jpg"),
		},

		{
			name:     "test/small.jpg raw",
			prefix:   rootSeparator,
			infoName: "test/small.jpg",
			result:   newTestInfo(oid, bkt, "test/small.jpg", rootSeparator),
			object:   newTestObject(oid, bkt, "test/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg",
			prefix:   "",
			infoName: "test/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", ""),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg",
			prefix:   "test",
			infoName: "a/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", "test"),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg",
			prefix:   "test/a",
			infoName: "b/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", "test/a"),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg",
			prefix:   "test/a/b",
			infoName: "c/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", "test/a/b"),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg with slash",
			prefix:   "test/a/b/",
			infoName: "c/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", "test/a/b/"),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg",
			prefix:   "test/a/b/c",
			infoName: "d/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", "test/a/b/c"),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},

		{
			name:     "test/a/b/c/d/e/f/g/h/small.jpg",
			prefix:   "test/a/b/c/d",
			infoName: "e/",
			result:   newTestInfo(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg", "test/a/b/c/d"),
			object:   newTestObject(oid, bkt, "test/a/b/c/d/e/f/g/h/small.jpg"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_"+tc.infoName, func(t *testing.T) {
			info := objectInfoFromMeta(bkt, tc.object, tc.prefix)
			require.Equal(t, tc.result, info)
			require.Equal(t, tc.infoName, info.Name)
		})
	}
}
