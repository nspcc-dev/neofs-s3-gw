package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

const (
	xAmzDecodedContentLength = "X-Amz-Decoded-Content-Length"
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
	var s3Err s3errors.Error
	if errors.As(err, &s3Err) {
		return s3Err
	}

	if errors.Is(err, layer.ErrAccessDenied) ||
		errors.Is(err, layer.ErrNodeAccessDenied) {
		return s3errors.GetAPIError(s3errors.ErrAccessDenied)
	}

	if errors.Is(err, layer.ErrMetaEmptyParameterValue) {
		return s3errors.GetAPIError(s3errors.ErrUnsupportedMetadata)
	}

	if errors.Is(err, errInvalidPublicKey) {
		return s3errors.GetAPIError(s3errors.ErrInvalidArgument)
	}

	if errors.Is(err, layer.ErrTooManyObjectForDeletion) {
		return s3errors.GetAPIError(s3errors.ErrBadRequest)
	}

	if errors.Is(err, layer.ErrDecodeUserID) {
		return s3errors.GetAPIError(s3errors.ErrInvalidArgument)
	}

	if errors.Is(err, apistatus.ErrContainerAwaitTimeout) {
		return s3errors.GetAPIError(s3errors.ErrOperationTimedOut)
	}

	return s3errors.GetAPIError(s3errors.ErrInternalError)
}

func (h *handler) getBucketAndCheckOwner(r *http.Request, bucket string, header ...string) (*data.BucketInfo, error) {
	bktInfo, err := h.obj.GetBucketInfo(r.Context(), bucket)
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

func parseRange(s string) (*layer.RangeParams, error) {
	if s == "" {
		return nil, nil
	}

	prefix := "bytes="

	if !strings.HasPrefix(s, prefix) {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidRange)
	}

	s = strings.TrimPrefix(s, prefix)

	valuesStr := strings.Split(s, "-")
	if len(valuesStr) != 2 {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidRange)
	}

	values := make([]uint64, 0, len(valuesStr))
	for _, v := range valuesStr {
		num, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidRange)
		}
		values = append(values, num)
	}
	if values[0] > values[1] {
		return nil, s3errors.GetAPIError(s3errors.ErrInvalidRange)
	}

	return &layer.RangeParams{
		Start: values[0],
		End:   values[1],
	}, nil
}

func getSessionTokenSetEACL(ctx context.Context) (*session.Container, error) {
	boxData, err := layer.GetBoxData(ctx)
	if err != nil {
		return nil, err
	}
	sessionToken := boxData.Gate.SessionTokenForSetEACL()
	if sessionToken == nil {
		return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
	}

	return sessionToken, nil
}

func contentLengthFromRequest(r *http.Request) (int64, error) {
	var (
		cl  = r.ContentLength
		err error
	)

	if value := r.Header.Get(xAmzDecodedContentLength); value != "" {
		cl, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid content length value %q inside %s header", value, xAmzDecodedContentLength)
		}
	}

	return cl, nil
}
