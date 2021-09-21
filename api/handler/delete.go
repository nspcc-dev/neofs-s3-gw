package handler

import (
	"encoding/xml"
	"net/http"
	"strconv"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DeleteObjectsRequest - xml carrying the object key names which needs to be deleted.
type DeleteObjectsRequest struct {
	// Element to enable quiet mode for the request
	Quiet bool
	// List of objects to be deleted
	Objects []ObjectIdentifier `xml:"Object"`
}

// ObjectIdentifier carries key name for the object to delete.
type ObjectIdentifier struct {
	ObjectName string `xml:"Key"`
	VersionID  string `xml:"VersionId,omitempty"`
}

// DeletedObject carries key name for the object to delete.
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

func (h *handler) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	versionedObject := []*layer.VersionedObject{{
		Name:      reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get(api.QueryVersionID),
	}}

	if err := h.checkBucketOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	deletedObjects, err := h.obj.DeleteObjects(r.Context(), reqInfo.BucketName, versionedObject)
	deletedObject := deletedObjects[0]
	if err == nil {
		err = deletedObject.Error
	}
	if err != nil {
		h.log.Error("could not delete object",
			zap.String("request_id", reqInfo.RequestID),
			zap.String("bucket_name", reqInfo.BucketName),
			zap.String("object_name", reqInfo.ObjectName),
			zap.Error(err))
	}

	if deletedObject.DeleteMarkVersion != "" {
		w.Header().Set(api.AmzDeleteMarker, strconv.FormatBool(true))
		w.Header().Set(api.AmzVersionID, deletedObject.DeleteMarkVersion)
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteMultipleObjectsHandler handles multiple delete requests.
func (h *handler) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	// Content-Md5 is requied should be set
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if _, ok := r.Header[api.ContentMD5]; !ok {
		h.logAndSendError(w, "missing Content-MD5", reqInfo, errors.GetAPIError(errors.ErrMissingContentMD5))
		return
	}

	// Content-Length is required and should be non-zero
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if r.ContentLength <= 0 {
		h.logAndSendError(w, "missing Content-Length", reqInfo, errors.GetAPIError(errors.ErrMissingContentLength))
		return
	}

	// Unmarshal list of keys to be deleted.
	requested := &DeleteObjectsRequest{}
	if err := xml.NewDecoder(r.Body).Decode(requested); err != nil {
		h.logAndSendError(w, "couldn't decode body", reqInfo, err)
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

	if err := h.checkBucketOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	marshaler := zapcore.ArrayMarshalerFunc(func(encoder zapcore.ArrayEncoder) error {
		for _, obj := range toRemove {
			encoder.AppendString(obj.String())
		}
		return nil
	})

	deletedObjects, err := h.obj.DeleteObjects(r.Context(), reqInfo.BucketName, toRemove)
	if !requested.Quiet && err != nil {
		h.logAndSendError(w, "couldn't delete objects", reqInfo, err)
		return
	}

	var errs []error
	for _, obj := range deletedObjects {
		if obj.Error == nil {
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
		} else if !requested.Quiet {
			code := "BadRequest"
			if s3err, ok := obj.Error.(errors.Error); ok {
				code = s3err.Code
			}
			response.Errors = append(response.Errors, DeleteError{
				Code:      code,
				Message:   obj.Error.Error(),
				Key:       obj.Name,
				VersionID: obj.VersionID,
			})
			errs = append(errs, obj.Error)
		}
	}

	if !requested.Quiet && len(errs) != 0 {
		additional := []zap.Field{
			zap.Array("objects", marshaler),
			zap.Errors("errors", errs),
		}
		h.logAndSendError(w, "could not delete objects", reqInfo, nil, additional...)
	}

	if err := api.EncodeToResponse(w, response); err != nil {
		h.logAndSendError(w, "could not write response", reqInfo, err, zap.Array("objects", marshaler))
		return
	}
}

func (h *handler) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	if err := h.checkBucketOwner(r, reqInfo.BucketName); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}
	if err := h.obj.DeleteBucket(r.Context(), &layer.DeleteBucketParams{Name: reqInfo.BucketName}); err != nil {
		h.logAndSendError(w, "couldn't delete bucket", reqInfo, err)
	}
	w.WriteHeader(http.StatusNoContent)
}
