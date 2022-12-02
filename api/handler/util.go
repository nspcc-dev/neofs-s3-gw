package handler

import (
	"context"
	"encoding/hex"
	errorsStd "errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler/encryption"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

func (h *handler) logAndSendError(w http.ResponseWriter, logText string, reqInfo *api.ReqInfo, err error, additional ...zap.Field) {
	code := api.WriteErrorResponse(w, reqInfo, transformToS3Error(err))
	fields := []zap.Field{
		zap.Int("status", code),
		zap.String("request_id", reqInfo.RequestID),
		zap.String("method", reqInfo.API),
		zap.String("bucket", reqInfo.BucketName),
		zap.String("object", reqInfo.ObjectName),
		zap.String("description", logText),
		zap.Error(err)}
	fields = append(fields, additional...)
	h.log.Error("call method", fields...)
}

func transformToS3Error(err error) error {
	if _, ok := err.(errors.Error); ok {
		return err
	}

	if errorsStd.Is(err, ErrAccessDenied) ||
		errorsStd.Is(err, ErrNodeAccessDenied) {
		return errors.GetAPIError(errors.ErrAccessDenied)
	}

	return errors.GetAPIError(errors.ErrInternalError)
}

func (h *handler) getBucketAndCheckOwner(r *http.Request, bucket string, header ...string) (*data.BucketInfo, error) {
	bktInfo, err := h.getBucketInfo(r.Context(), bucket)
	if err != nil {
		return nil, err
	}

	var expected string
	if len(header) == 0 {
		expected = r.Header.Get(api.AmzExpectedBucketOwner)
	} else {
		expected = r.Header.Get(header[0])
	}

	if len(expected) == 0 {
		return bktInfo, nil
	}

	return bktInfo, checkOwner(bktInfo, expected)
}

func parseRange(s string) (*RangeParams, error) {
	if s == "" {
		return nil, nil
	}

	prefix := "bytes="

	if !strings.HasPrefix(s, prefix) {
		return nil, errors.GetAPIError(errors.ErrInvalidRange)
	}

	s = strings.TrimPrefix(s, prefix)

	valuesStr := strings.Split(s, "-")
	if len(valuesStr) != 2 {
		return nil, errors.GetAPIError(errors.ErrInvalidRange)
	}

	values := make([]uint64, 0, len(valuesStr))
	for _, v := range valuesStr {
		num, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, errors.GetAPIError(errors.ErrInvalidRange)
		}
		values = append(values, num)
	}
	if values[0] > values[1] {
		return nil, errors.GetAPIError(errors.ErrInvalidRange)
	}

	return &RangeParams{
		Start: values[0],
		End:   values[1],
	}, nil
}

func getSessionTokenSetEACL(ctx context.Context) (*session.Container, error) {
	boxData, err := GetBoxData(ctx)
	if err != nil {
		return nil, err
	}
	sessionToken := boxData.Gate.SessionTokenForSetEACL()
	if sessionToken == nil {
		return nil, errors.GetAPIError(errors.ErrAccessDenied)
	}

	return sessionToken, nil
}

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

// PathSeparator is a path components separator string.
const PathSeparator = string(os.PathSeparator)

func userHeaders(attrs []object.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))

	for _, attr := range attrs {
		result[attr.Key()] = attr.Value()
	}

	return result
}

func objectInfoFromMeta(bkt *data.BucketInfo, meta *object.Object) *data.ObjectInfo {
	var (
		mimeType string
		creation time.Time
	)

	headers := userHeaders(meta.Attributes())
	delete(headers, object.AttributeFilePath)
	if contentType, ok := headers[object.AttributeContentType]; ok {
		mimeType = contentType
		delete(headers, object.AttributeContentType)
	}
	if val, ok := headers[object.AttributeTimestamp]; !ok {
		// ignore empty value
	} else if dt, err := strconv.ParseInt(val, 10, 64); err == nil {
		creation = time.Unix(dt, 0)
		delete(headers, object.AttributeTimestamp)
	}

	objID, _ := meta.ID()
	payloadChecksum, _ := meta.PayloadChecksum()
	return &data.ObjectInfo{
		ID:    objID,
		CID:   bkt.CID,
		IsDir: false,

		Bucket:      bkt.Name,
		Name:        filepathFromObject(meta),
		Created:     creation,
		ContentType: mimeType,
		Headers:     headers,
		Owner:       *meta.OwnerID(),
		Size:        int64(meta.PayloadSize()),
		HashSum:     hex.EncodeToString(payloadChecksum.Value()),
	}
}

func FormEncryptionInfo(headers map[string]string) encryption.ObjectEncryption {
	algorithm := headers[AttributeEncryptionAlgorithm]
	return encryption.ObjectEncryption{
		Enabled:   len(algorithm) > 0,
		Algorithm: algorithm,
		HMACKey:   headers[AttributeHMACKey],
		HMACSalt:  headers[AttributeHMACSalt],
	}
}

func addEncryptionHeaders(meta map[string]string, enc encryption.Params) error {
	meta[AttributeEncryptionAlgorithm] = AESEncryptionAlgorithm
	hmacKey, hmacSalt, err := enc.HMAC()
	if err != nil {
		return fmt.Errorf("get hmac: %w", err)
	}
	meta[AttributeHMACKey] = hex.EncodeToString(hmacKey)
	meta[AttributeHMACSalt] = hex.EncodeToString(hmacSalt)

	return nil
}

func filepathFromObject(o *object.Object) string {
	for _, attr := range o.Attributes() {
		if attr.Key() == object.AttributeFilePath {
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
