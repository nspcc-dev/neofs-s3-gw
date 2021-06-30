package layer

import (
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
		HashSum     string
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

// PathSeparator is a path components separator string.
const PathSeparator = string(os.PathSeparator)

func userHeaders(attrs []*object.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		result[attr.Key()] = attr.Value()
	}

	return result
}

func objectInfoFromMeta(bkt *BucketInfo, meta *object.Object, prefix, delimiter string) *ObjectInfo {
	var (
		isDir    bool
		size     int64
		mimeType string
		creation time.Time
		filename = filenameFromObject(meta)
	)

	if !strings.HasPrefix(filename, prefix) {
		return nil
	}

	userHeaders := userHeaders(meta.Attributes())
	delete(userHeaders, object.AttributeFileName)
	if contentType, ok := userHeaders[object.AttributeContentType]; ok {
		mimeType = contentType
		delete(userHeaders, object.AttributeContentType)
	}
	if val, ok := userHeaders[object.AttributeTimestamp]; !ok {
		// ignore empty value
	} else if dt, err := strconv.ParseInt(val, 10, 64); err == nil {
		creation = time.Unix(dt, 0)
		delete(userHeaders, object.AttributeTimestamp)
	}

	if len(delimiter) > 0 {
		tail := strings.TrimPrefix(filename, prefix)
		index := strings.Index(tail, delimiter)
		if index >= 0 {
			isDir = true
			filename = prefix + tail[:index+1]
			userHeaders = nil
		} else {
			size = int64(meta.PayloadSize())
		}
	} else {
		size = int64(meta.PayloadSize())
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
		HashSum:     meta.PayloadChecksum().String(),
	}
}

func filenameFromObject(o *object.Object) string {
	var name = o.ID().String()
	for _, attr := range o.Attributes() {
		if attr.Key() == object.AttributeFileName {
			return attr.Value()
		}
	}
	return name
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
