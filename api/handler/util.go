package handler

import (
	"net/http"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"go.uber.org/zap"
)

func (h *handler) logAndSendError(w http.ResponseWriter, logText string, reqInfo *api.ReqInfo, err error, additional ...zap.Field) {
	fields := []zap.Field{zap.String("request_id", reqInfo.RequestID),
		zap.String("method", reqInfo.API),
		zap.String("bucket_name", reqInfo.BucketName),
		zap.String("object_name", reqInfo.ObjectName),
		zap.Error(err)}
	fields = append(fields, additional...)

	h.log.Error(logText, fields...)
	api.WriteErrorResponse(w, reqInfo, err)
}

func (h *handler) checkBucketOwner(r *http.Request, bucket string, header ...string) error {
	var expected string
	if len(header) == 0 {
		expected = r.Header.Get(api.AmzExpectedBucketOwner)
	} else {
		expected = header[0]
	}

	if len(expected) == 0 {
		return nil
	}

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), bucket)
	if err != nil {
		return err
	}

	return checkOwner(bktInfo, expected)
}
