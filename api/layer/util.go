package layer

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
)

type (
	// ObjectInfo holds S3 object data.
	ObjectInfo struct {
		id    *object.ID
		isDir bool

		Bucket      string
		Name        string
		Size        int64
		ContentType string
		Created     time.Time
		Owner       *owner.ID
		Headers     map[string]string
	}

	// ListObjectsInfo - container for list objects.
	ListObjectsInfo struct {
		// Indicates whether the returned list objects response is truncated. A
		// value of true indicates that the list was truncated. The list can be truncated
		// if the number of objects exceeds the limit allowed or specified
		// by max keys.
		IsTruncated bool

		// When response is truncated (the IsTruncated element value in the response
		// is true), you can use the key name in this field as marker in the subsequent
		// request to get next set of objects.
		//
		// NOTE: This element is returned only if you have delimiter request parameter
		// specified.
		ContinuationToken     string
		NextContinuationToken string

		// When response is truncated (the IsTruncated element value in the response is true),
		// you can use the key name in this field as marker in the subsequent request to get next set of objects.
		NextMarker string

		// List of objects info for this request.
		Objects []*ObjectInfo

		// List of prefixes for this request.
		Prefixes []string
	}
)

const (
	rootSeparator = "root://"
	// PathSeparator is a path components separator string.
	PathSeparator = string(os.PathSeparator)
)

func userHeaders(attrs []*object.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		result[attr.Key()] = attr.Value()
	}

	return result
}

func objectInfoFromMeta(bkt *BucketInfo, meta *object.Object, prefix string) *ObjectInfo {
	var (
		isDir         bool
		size          int64
		mimeType      string
		creation      time.Time
		filename      = meta.ID().String()
		name, dirname = nameFromObject(meta)
	)

	if !strings.HasPrefix(dirname, prefix) && prefix != rootSeparator {
		return nil
	}

	if ln := len(prefix); ln > 0 && prefix[ln-1:] != PathSeparator {
		prefix += PathSeparator
	}

	userHeaders := userHeaders(meta.Attributes())
	if val, ok := userHeaders[object.AttributeFileName]; ok {
		filename = val
		delete(userHeaders, object.AttributeFileName)
	}

	if val, ok := userHeaders[object.AttributeTimestamp]; !ok {
		// ignore empty value
	} else if dt, err := strconv.ParseInt(val, 10, 64); err == nil {
		creation = time.Unix(dt, 0)
		delete(userHeaders, object.AttributeTimestamp)
	}

	tail := strings.TrimPrefix(dirname, prefix)
	index := strings.Index(tail, PathSeparator)

	if prefix == rootSeparator {
		size = int64(meta.PayloadSize())
		mimeType = http.DetectContentType(meta.Payload())
	} else if index < 0 {
		filename = name
		size = int64(meta.PayloadSize())
		mimeType = http.DetectContentType(meta.Payload())
	} else {
		isDir = true
		filename = tail[:index] + PathSeparator
		userHeaders = nil
	}

	return &ObjectInfo{
		id:    meta.ID(),
		isDir: isDir,

		Bucket:      bkt.Name,
		Name:        filename,
		Created:     creation,
		ContentType: mimeType,
		Headers:     userHeaders,
		Owner:       meta.OwnerID(),
		Size:        size,
	}
}

func nameFromObject(o *object.Object) (string, string) {
	var name = o.ID().String()

	for _, attr := range o.Attributes() {
		if attr.Key() == object.AttributeFileName {
			name = attr.Value()

			break
		}
	}

	return NameFromString(name)
}

// NameFromString splits name into base file name and directory path.
func NameFromString(name string) (string, string) {
	ind := strings.LastIndex(name, PathSeparator)
	return name[ind+1:], name[:ind+1]
}

// ID returns object ID from ObjectInfo.
func (o *ObjectInfo) ID() *object.ID { return o.id }

// IsDir allows to check if object is a directory.
func (o *ObjectInfo) IsDir() bool { return o.isDir }
