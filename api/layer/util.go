package layer

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
)

type (
	// ObjectInfo holds S3 object data.
	ObjectInfo struct {
		id       *object.ID
		bucketID *cid.ID
		isDir    bool

		Bucket        string
		Name          string
		Size          int64
		ContentType   string
		Created       time.Time
		CreationEpoch uint64
		HashSum       string
		Owner         *owner.ID
		Headers       map[string]string
	}

	// ListObjectsInfo contains common fields of data for ListObjectsV1 and ListObjectsV2.
	ListObjectsInfo struct {
		Prefixes    []string
		Objects     []*ObjectInfo
		IsTruncated bool
	}

	// ListObjectsInfoV1 holds data which ListObjectsV1 returns.
	ListObjectsInfoV1 struct {
		ListObjectsInfo
		NextMarker string
	}

	// ListObjectsInfoV2 holds data which ListObjectsV2 returns.
	ListObjectsInfoV2 struct {
		ListObjectsInfo
		NextContinuationToken string
	}

	// ObjectVersionInfo stores info about objects versions.
	ObjectVersionInfo struct {
		Object   *ObjectInfo
		IsLatest bool
	}

	// ListObjectVersionsInfo stores info and list of objects' versions.
	ListObjectVersionsInfo struct {
		CommonPrefixes      []string
		IsTruncated         bool
		KeyMarker           string
		NextKeyMarker       string
		NextVersionIDMarker string
		Version             []*ObjectVersionInfo
		DeleteMarker        []*ObjectVersionInfo
		VersionIDMarker     string
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

func objInfoFromMeta(bkt *cache.BucketInfo, meta *object.Object) *ObjectInfo {
	return objectInfoFromMeta(bkt, meta, "", "")
}

func objectInfoFromMeta(bkt *cache.BucketInfo, meta *object.Object, prefix, delimiter string) *ObjectInfo {
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
			mimeType = ""
			filename = prefix + tail[:index+1]
			userHeaders = nil
		} else {
			size = int64(meta.PayloadSize())
		}
	} else {
		size = int64(meta.PayloadSize())
	}

	return &ObjectInfo{
		id:       meta.ID(),
		bucketID: bkt.CID,
		isDir:    isDir,

		Bucket:        bkt.Name,
		Name:          filename,
		Created:       creation,
		CreationEpoch: meta.CreationEpoch(),
		ContentType:   mimeType,
		Headers:       userHeaders,
		Owner:         meta.OwnerID(),
		Size:          size,
		HashSum:       meta.PayloadChecksum().String(),
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

// Version returns object version from ObjectInfo.
func (o *ObjectInfo) Version() string { return o.id.String() }

// NiceName returns object name for cache.
func (o *ObjectInfo) NiceName() string { return o.Bucket + "/" + o.Name }

// Address returns object address.
func (o *ObjectInfo) Address() *object.Address { return newAddress(o.bucketID, o.id) }

// TagsObject returns name of system object for tags.
func (o *ObjectInfo) TagsObject() string { return ".tagset." + o.Name + "." + o.Version() }

// CID returns bucket ID from ObjectInfo.
func (o *ObjectInfo) CID() *cid.ID { return o.bucketID }

// IsDir allows to check if object is a directory.
func (o *ObjectInfo) IsDir() bool { return o.isDir }

// GetBoxData  extracts accessbox.Box from context.
func GetBoxData(ctx context.Context) (*accessbox.Box, error) {
	var boxData *accessbox.Box
	data, ok := ctx.Value(api.BoxData).(*accessbox.Box)
	if !ok || data == nil {
		return nil, fmt.Errorf("couldn't get box data from context")
	}

	boxData = data
	if boxData.Gate == nil {
		boxData.Gate = &accessbox.GateData{}
	}
	return boxData, nil
}

func formBucketTagObjectName(name string) string {
	return ".tagset." + name
}
