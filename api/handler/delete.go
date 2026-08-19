package handler

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"go.uber.org/zap"
)

// DeleteObjectsRequest -- xml carrying the object key names which should be deleted.
type DeleteObjectsRequest struct {
	// Element to enable quiet mode for the request
	Quiet bool
	// List of objects to be deleted
	Objects []ObjectIdentifier `xml:"Object"`
}

// ObjectIdentifier carries the key name for the object to delete.
type ObjectIdentifier struct {
	ObjectName string `xml:"Key"`
	VersionID  string `xml:"VersionId,omitempty"`
}

// DeletedObject carries the key name for the object to delete.
type DeletedObject struct {
	ObjectIdentifier
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
}

// DeleteError structure.
type DeleteError struct {
	Code      string
	Message   string
	Key       string
	VersionID string `xml:"versionId,omitempty"`
}

// DeleteObjectsResponse container for multiple object deletes.
type DeleteObjectsResponse struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult" json:"-"`

	// Collection of all deleted objects
	DeletedObjects []DeletedObject `xml:"Deleted,omitempty"`

	// Collection of errors deleting certain objects.
	Errors []DeleteError `xml:"Error,omitempty"`
}

const (
	maxObjectsInErrorLog = 10
)

func (h *handler) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	versionID := reqInfo.URL.Query().Get(api.QueryVersionID)
	versionedObject := []*layer.VersionedObject{{
		Name:      reqInfo.ObjectName,
		VersionID: versionID,
	}}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.DeleteObjectParams{
		BktInfo:  bktInfo,
		Objects:  versionedObject,
		Settings: bktInfo.Settings,
	}
	deletedObjects := h.obj.DeleteObjects(r.Context(), p)
	deletedObject := deletedObjects[0]
	if deletedObject.Error != nil {
		if isErrObjectLocked(deletedObject.Error) {
			h.logAndSendError(w, "object is locked", reqInfo, s3errors.GetAPIError(s3errors.ErrAccessDenied))
		} else {
			h.logAndSendError(w, "could not delete object", reqInfo, deletedObject.Error)
		}
		return
	}

	var m *SendNotificationParams

	if bktInfo.Settings.VersioningEnabled() && len(versionID) == 0 {
		m = &SendNotificationParams{
			Event: EventObjectRemovedDeleteMarkerCreated,
			NotificationInfo: &data.NotificationInfo{
				Name:    reqInfo.ObjectName,
				HashSum: deletedObject.DeleteMarkerEtag,
			},
			BktInfo: bktInfo,
			ReqInfo: reqInfo,
		}
	} else {
		var objID oid.ID
		if len(versionID) != 0 {
			if err = objID.DecodeString(versionID); err != nil {
				h.log.Error("couldn't send notification: %w", zap.Error(err))
			}
		}

		m = &SendNotificationParams{
			Event: EventObjectRemovedDelete,
			NotificationInfo: &data.NotificationInfo{
				Name:    reqInfo.ObjectName,
				Version: objID.EncodeToString(),
			},
			BktInfo: bktInfo,
			ReqInfo: reqInfo,
		}
	}

	if err = h.sendNotifications(r.Context(), m); err != nil {
		h.log.Error("couldn't send notification: %w", zap.Error(err))
	}

	if deletedObject.VersionID != "" {
		w.Header().Set(api.AmzVersionID, deletedObject.VersionID)
	}
	if deletedObject.DeleteMarkVersion != "" {
		w.Header().Set(api.AmzDeleteMarker, strconv.FormatBool(true))
		if deletedObject.VersionID == "" {
			w.Header().Set(api.AmzVersionID, deletedObject.DeleteMarkVersion)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func isErrObjectLocked(err error) bool {
	var (
		ol  apistatus.ObjectLocked
		olp *apistatus.ObjectLocked
	)
	switch {
	case errors.As(err, &ol), errors.As(err, &olp):
		return true
	default:
		return strings.Contains(err.Error(), "object is locked")
	}
}

// DeleteMultipleObjectsHandler handles multiple delete requests.
func (h *handler) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	// Content-Length is required and should be non-zero
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if r.ContentLength <= 0 {
		h.logAndSendError(w, "missing Content-Length", reqInfo, s3errors.GetAPIError(s3errors.ErrMissingContentLength))
		return
	}

	// Unmarshal list of keys to be deleted.
	requested := &DeleteObjectsRequest{}
	if err := xml.NewDecoder(r.Body).Decode(requested); err != nil {
		h.logAndSendError(w, "couldn't decode body", reqInfo, s3errors.GetAPIError(s3errors.ErrMalformedXML))
		return
	}

	if len(requested.Objects) > h.cfg.MaxDeletePerRequest {
		h.logAndSendError(w, "too many objects to delete", reqInfo, layer.ErrTooManyObjectForDeletion)
		return
	}

	removed := make(map[string]*layer.VersionedObject)
	toRemove := make([]*layer.VersionedObject, 0, len(requested.Objects))
	for _, obj := range requested.Objects {
		versionedObj := &layer.VersionedObject{
			Name:      obj.ObjectName,
			VersionID: obj.VersionID,
		}
		toRemove = append(toRemove, versionedObj)
		removed[versionedObj.String()] = versionedObj
	}

	response := &DeleteObjectsResponse{
		Errors:         make([]DeleteError, 0, len(toRemove)),
		DeletedObjects: make([]DeletedObject, 0, len(toRemove)),
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.DeleteObjectParams{
		BktInfo:  bktInfo,
		Objects:  toRemove,
		Settings: bktInfo.Settings,
	}
	deletedObjects := h.obj.DeleteObjects(r.Context(), p)

	var (
		errs     []error
		failed   []*layer.VersionedObject
		canceled int
	)
	for _, obj := range deletedObjects {
		if obj.Error != nil {
			var (
				code  = "BadRequest"
				s3err s3errors.Error
			)

			if errors.As(obj.Error, &s3err) {
				code = s3err.Code
			}
			response.Errors = append(response.Errors, DeleteError{
				Code:      code,
				Message:   obj.Error.Error(),
				Key:       obj.Name,
				VersionID: obj.VersionID,
			})

			if errors.Is(obj.Error, context.Canceled) || errors.Is(obj.Error, context.DeadlineExceeded) {
				canceled++
			} else {
				errs = append(errs, obj.Error)
				failed = append(failed, obj)
			}
		} else if !requested.Quiet {
			deletedObj := DeletedObject{
				ObjectIdentifier: ObjectIdentifier{
					ObjectName: obj.Name,
					VersionID:  obj.VersionID,
				},
				DeleteMarkerVersionID: obj.DeleteMarkVersion,
			}
			if deletedObj.DeleteMarkerVersionID != "" {
				deletedObj.DeleteMarker = true
			}
			response.DeletedObjects = append(response.DeletedObjects, deletedObj)
		}
	}
	if len(errs) != 0 {
		var (
			n      = min(maxObjectsInErrorLog, len(errs))
			fields = []zap.Field{
				zap.Stringers("objects", failed[:n]),
				zap.Errors("errors", errs[:n]),
				zap.Int("total_objects", len(toRemove)),
				zap.Int("total_errors", len(errs)),
			}
		)

		h.log.Error("couldn't delete objects", fields...)
	}
	if canceled != 0 {
		h.log.Debug("deletion interrupted by the client",
			zap.String("request_id", reqInfo.RequestID),
			zap.Int("canceled_objects", canceled),
			zap.Int("total_objects", len(toRemove)))
	}

	if err = api.EncodeToResponse(w, response); err != nil {
		// The status and a part of the body are written already, an error response can't be sent anymore.
		h.log.Error("could not write response",
			zap.String("request_id", reqInfo.RequestID),
			zap.String("bucket", reqInfo.BucketName),
			zap.Error(err),
			zap.Stringers("objects", toRemove[:min(maxObjectsInErrorLog, len(toRemove))]),
			zap.Int("total_objects", len(toRemove)))
		return
	}
}

func (h *handler) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var sessionTokenV2 *session.Token

	boxData, err := layer.GetBoxData(r.Context())
	if err == nil {
		sessionTokenV2 = boxData.Gate.SessionTokenV2
	}

	if err = h.obj.DeleteBucket(r.Context(), &layer.DeleteBucketParams{
		BktInfo:        bktInfo,
		SessionTokenV2: sessionTokenV2,
	}); err != nil {
		h.logAndSendError(w, "couldn't delete bucket", reqInfo, err)
	}
	w.WriteHeader(http.StatusNoContent)
}
