package layer

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
)

type (
	ObjectInfo struct {
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

func objectInfoFromMeta(meta *object.Object) *ObjectInfo {
	aws3name := meta.GetID().String()

	userHeaders := userHeaders(meta.GetAttributes())
	if name, ok := userHeaders[AWS3NameHeader]; ok {
		aws3name = name
		delete(userHeaders, name)
	}

	mimeType := http.DetectContentType(meta.GetPayload())

	return &ObjectInfo{
		Bucket:      meta.GetContainerID().String(),
		Name:        aws3name,
		ContentType: mimeType,
		Headers:     userHeaders,
		Size:        int64(meta.GetPayloadSize()),
		Created:     time.Now(), // time.Unix(meta.GetCreationEpoch(), 0),
	}
}

func nameFromObject(o *object.Object) (string, string) {
	var name = o.GetID().String()

	for _, attr := range o.GetAttributes() {
		if attr.GetKey() == AWS3NameHeader {
			name = attr.GetValue()

			break
		}
	}

	ind := strings.LastIndex(name, pathSeparator)

	return name[ind+1:], name[:ind+1]
}
