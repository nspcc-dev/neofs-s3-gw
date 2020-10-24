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
	ObjectInfo struct {
		id *object.ID

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

		// List of objects info for this request.
		Objects []*ObjectInfo

		// List of prefixes for this request.
		Prefixes []string
	}
)

const pathSeparator = string(os.PathSeparator)

func userHeaders(attrs []*object.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		result[attr.GetKey()] = attr.GetValue()
	}

	return result
}

func objectInfoFromMeta(bkt *BucketInfo, meta *object.Object) *ObjectInfo {
	var (
		creation time.Time
		filename = meta.GetID().String()
	)

	userHeaders := userHeaders(meta.GetAttributes())
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

	mimeType := http.DetectContentType(meta.GetPayload())

	return &ObjectInfo{
		id: meta.GetID(),

		Bucket:      bkt.Name,
		Name:        filename,
		Created:     creation,
		ContentType: mimeType,
		Headers:     userHeaders,
		Size:        int64(meta.GetPayloadSize()),
	}
}

func nameFromObject(o *object.Object) (string, string) {
	var name = o.GetID().String()

	for _, attr := range o.GetAttributes() {
		if attr.GetKey() == object.AttributeFileName {
			name = attr.GetValue()

			break
		}
	}

	ind := strings.LastIndex(name, pathSeparator)

	return name[ind+1:], name[:ind+1]
}

func (o *ObjectInfo) ID() *object.ID { return o.id }
