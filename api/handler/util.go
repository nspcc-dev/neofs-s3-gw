package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/internal/misc"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

func (h *handler) logAndSendError(w http.ResponseWriter, logText string, reqInfo *api.ReqInfo, err error, additional ...zap.Field) {
	fields := []zap.Field{zap.String("request_id", misc.SanitizeString(reqInfo.RequestID)),
		zap.String("method", misc.SanitizeString(reqInfo.API)),
		zap.String("bucket_name", misc.SanitizeString(reqInfo.BucketName)),
		zap.String("object_name", misc.SanitizeString(reqInfo.ObjectName)),
		zap.Error(err)}
	fields = append(fields, additional...)

	h.log.Error(logText, fields...)
	api.WriteErrorResponse(w, reqInfo, err)
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
		return nil, errors.GetAPIError(errors.ErrAccessDenied)
	}

	return sessionToken, nil
}
