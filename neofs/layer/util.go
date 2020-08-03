package layer

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-api-go/object"
)

type (
	ObjectInfo struct {
		Bucket      string
		Name        string
		Size        int64
		ContentType string
		Created     time.Time
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
		Objects []ObjectInfo

		// List of prefixes for this request.
		Prefixes []string
	}
)

const pathSeparator = string(os.PathSeparator)

func userHeaders(h []object.Header) map[string]string {
	result := make(map[string]string, len(h))

	for i := range h {
		switch v := h[i].Value.(type) {
		case *object.Header_UserHeader:
			result[v.UserHeader.Key] = v.UserHeader.Value
		default:
			continue
		}
	}

	return result
}

func objectInfoFromMeta(meta *object.Object) *ObjectInfo {
	aws3name := meta.SystemHeader.ID.String()

	userHeaders := userHeaders(meta.Headers)
	if name, ok := userHeaders[AWS3NameHeader]; ok {
		aws3name = name
		delete(userHeaders, name)
	}

	mimeType := http.DetectContentType(meta.Payload)

	return &ObjectInfo{
		Bucket:      meta.SystemHeader.CID.String(),
		Name:        aws3name,
		ContentType: mimeType,
		Headers:     userHeaders,
		Size:        int64(meta.SystemHeader.PayloadLength),
		Created:     time.Unix(meta.SystemHeader.CreatedAt.UnixTime, 0),
	}
}

func parseUserHeaders(h map[string]string) []object.Header {
	headers := make([]object.Header, 0, len(h))

	for k, v := range h {
		uh := &object.UserHeader{Key: k, Value: v}
		headers = append(headers, object.Header{
			Value: &object.Header_UserHeader{UserHeader: uh},
		})
	}

	return headers
}

func nameFromObject(o *object.Object) (string, string) {
	var (
		name string
		uh   = userHeaders(o.Headers)
	)

	if _, ok := uh[AWS3NameHeader]; !ok {
		name = o.SystemHeader.ID.String()
	} else {
		name = uh[AWS3NameHeader]
	}

	ind := strings.LastIndex(name, pathSeparator)

	return name[ind+1:], name[:ind+1]
}
