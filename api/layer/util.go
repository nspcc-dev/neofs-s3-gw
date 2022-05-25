package layer

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/object"
)

type (
	// ListObjectsInfo contains common fields of data for ListObjectsV1 and ListObjectsV2.
	ListObjectsInfo struct {
		Prefixes    []string
		Objects     []*data.ObjectInfo
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
		Object   *data.ObjectInfo
		IsLatest bool
	}

	// ListObjectVersionsInfo stores info and list of objects versions.
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

func userHeaders(attrs []object.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		result[attr.Key()] = attr.Value()
	}

	return result
}

func objInfoFromMeta(bkt *data.BucketInfo, meta *object.Object) *data.ObjectInfo {
	return objectInfoFromMeta(bkt, meta, "", "")
}

func objectInfoFromMeta(bkt *data.BucketInfo, meta *object.Object, prefix, delimiter string) *data.ObjectInfo {
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

	objID, _ := meta.ID()
	payloadChecksum, _ := meta.PayloadChecksum()
	return &data.ObjectInfo{
		ID:    objID,
		CID:   bkt.CID,
		IsDir: isDir,

		Bucket:        bkt.Name,
		Name:          filename,
		Created:       creation,
		CreationEpoch: meta.CreationEpoch(),
		ContentType:   mimeType,
		Headers:       userHeaders,
		Owner:         *meta.OwnerID(),
		Size:          size,
		HashSum:       hex.EncodeToString(payloadChecksum.Value()),
	}
}

func filenameFromObject(o *object.Object) string {
	for _, attr := range o.Attributes() {
		if attr.Key() == object.AttributeFileName {
			return attr.Value()
		}
	}
	objID, _ := o.ID()
	return objID.EncodeToString()
}

// NameFromString splits name into a base file name and a directory path.
func NameFromString(name string) (string, string) {
	ind := strings.LastIndex(name, PathSeparator)
	return name[ind+1:], name[:ind+1]
}

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
