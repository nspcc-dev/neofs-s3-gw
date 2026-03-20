package layer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

type (
	// ListObjectsInfo contains common fields of data for ListObjectsV1 and ListObjectsV2.
	ListObjectsInfo struct {
		Prefixes    []string
		Objects     []data.ObjectListResponseContent
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

	// ListObjectVersionsInfo stores info and list of objects versions.
	ListObjectVersionsInfo struct {
		CommonPrefixes      []string
		IsTruncated         bool
		KeyMarker           string
		NextKeyMarker       string
		NextVersionIDMarker string
		Version             []*data.ExtendedObjectInfo
		DeleteMarker        []*data.ExtendedObjectInfo
		VersionIDMarker     string
	}
)

var (
	// ErrLinkingObjectNotFound means there is no linking object for parent.
	ErrLinkingObjectNotFound = errors.New("linking object not found")
)

func userHeaders(attrs []object.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		result[attr.Key()] = attr.Value()
	}

	return result
}

func extractHeaders(headers map[string]string) (map[string]string, string, time.Time) {
	var (
		mimeType string
		creation time.Time
	)

	delete(headers, object.AttributeFilePath)
	delete(headers, s3headers.AttributeObjectNonce)

	if contentType, ok := headers[object.AttributeContentType]; ok {
		mimeType = contentType
		delete(headers, object.AttributeContentType)
	}

	if val, ok := headers[object.AttributeTimestamp]; ok {
		if dt, err := strconv.ParseInt(val, 10, 64); err == nil {
			creation = time.Unix(dt, 0)
			delete(headers, object.AttributeTimestamp)
		}
	}

	return headers, mimeType, creation
}

func objectInfoFromMeta(bkt *data.BucketInfo, meta *object.Object) *data.ObjectInfo {
	attributes := userHeaders(meta.Attributes())
	customHeaders, mimeType, creation := extractHeaders(attributes)

	objID := meta.GetID()
	payloadChecksum, _ := meta.PayloadChecksum()

	var versionID = data.UnversionedObjectVersionID
	if _, ok := attributes[s3headers.AttributeVersioningState]; ok {
		versionID = objID.EncodeToString()
	}

	return &data.ObjectInfo{
		ID:    objID,
		CID:   bkt.CID,
		IsDir: false,

		Bucket:      bkt.Name,
		Name:        filepathFromObject(meta),
		Created:     creation,
		ContentType: mimeType,
		Headers:     customHeaders,
		Owner:       meta.Owner(),
		Size:        int64(meta.PayloadSize()),
		HashSum:     hex.EncodeToString(payloadChecksum.Value()),
		Version:     versionID,
	}
}

func FormEncryptionInfo(headers map[string]string) encryption.ObjectEncryption {
	algorithm := headers[s3headers.AttributeEncryptionAlgorithm]
	return encryption.ObjectEncryption{
		Enabled:   len(algorithm) > 0,
		Algorithm: algorithm,
		HMACKey:   headers[s3headers.AttributeHMACKey],
		HMACSalt:  headers[s3headers.AttributeHMACSalt],
	}
}

func addEncryptionHeaders(meta map[string]string, enc encryption.Params) error {
	meta[s3headers.AttributeEncryptionAlgorithm] = AESEncryptionAlgorithm
	hmacKey, hmacSalt, err := enc.HMAC()
	if err != nil {
		return fmt.Errorf("get hmac: %w", err)
	}
	meta[s3headers.AttributeHMACKey] = hex.EncodeToString(hmacKey)
	meta[s3headers.AttributeHMACSalt] = hex.EncodeToString(hmacSalt)

	return nil
}

func filepathFromObject(o *object.Object) string {
	for _, attr := range o.Attributes() {
		if attr.Key() == object.AttributeFilePath {
			return attr.Value()
		}
	}
	return o.GetID().EncodeToString()
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

func (n *layer) GetMultipartParts(ctx context.Context, bktInfo *data.BucketInfo, parentID oid.ID) ([]object.MeasuredObject, string, error) {
	searchLinkingObject, err := n.SearchLinkingObject(ctx, bktInfo, parentID)
	if err != nil {
		return nil, "", fmt.Errorf("linking object search failed: %w", err)
	}

	if searchLinkingObject.ID.IsZero() {
		return nil, "", ErrLinkingObjectNotFound
	}

	linkingObject, err := n.GetLinkingObject(ctx, bktInfo, searchLinkingObject.ID)
	if err != nil {
		return nil, "", fmt.Errorf("linking object get failed: %w", err)
	}

	var measuredObjects = linkingObject.Objects()
	// two meta parts + as minimum one payload part.
	if len(measuredObjects) < 3 {
		return nil, "", errors.New("linking object should have at least 3 parts")
	}

	// first and last elements are metadata parts with zero length.
	var completedParts = measuredObjects[1 : len(measuredObjects)-1]

	return completedParts, searchLinkingObject.MultipartUpload, nil
}
