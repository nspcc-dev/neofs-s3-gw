package handler

import (
	"encoding/xml"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nspcc-dev/neofs-s3-gate/api"
	"go.uber.org/zap"
	"google.golang.org/grpc/status"
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
}

// DeleteError structure.
type DeleteError struct {
	Code    string
	Message string
	Key     string
}

// DeleteObjectsResponse container for multiple object deletes.
type DeleteObjectsResponse struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult" json:"-"`

	// Collection of all deleted objects
	DeletedObjects []ObjectIdentifier `xml:"Deleted,omitempty"`

	// Collection of errors deleting certain objects.
	Errors []DeleteError `xml:"Error,omitempty"`
}

func (h *handler) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {
	var (
		req = mux.Vars(r)
		bkt = req["bucket"]
		obj = req["object"]
		rid = api.GetRequestID(r.Context())
	)

	if err := h.obj.DeleteObject(r.Context(), bkt, obj); err != nil {
		h.log.Error("could not delete object",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.String("object_name", obj),
			zap.Error(err))

		// Ignore delete errors:

		// api.WriteErrorResponse(r.Context(), w, api.Error{
		// 	Code:           api.GetAPIError(api.ErrInternalError).Code,
		// 	Description:    err.Error(),
		// 	HTTPStatusCode: http.StatusInternalServerError,
		// }, r.URL)
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteMultipleObjectsHandler :
func (h *handler) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		req = mux.Vars(r)
		bkt = req["bucket"]
		rid = api.GetRequestID(r.Context())
	)

	// Content-Md5 is requied should be set
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if _, ok := r.Header[api.ContentMD5]; !ok {
		api.WriteErrorResponse(r.Context(), w, api.GetAPIError(api.ErrMissingContentMD5), r.URL)
		return
	}

	// Content-Length is required and should be non-zero
	// http://docs.aws.amazon.com/AmazonS3/latest/API/multiobjectdeleteapi.html
	if r.ContentLength <= 0 {
		api.WriteErrorResponse(r.Context(), w, api.GetAPIError(api.ErrMissingContentLength), r.URL)
		return
	}

	// Unmarshal list of keys to be deleted.
	requested := &DeleteObjectsRequest{}
	if err := xml.NewDecoder(r.Body).Decode(requested); err != nil {
		api.WriteErrorResponse(r.Context(), w, err, r.URL)
		return
	}

	removed := make(map[string]struct{})
	toRemove := make([]string, 0, len(requested.Objects))
	for _, obj := range requested.Objects {
		removed[obj.ObjectName] = struct{}{}
		toRemove = append(toRemove, obj.ObjectName)
	}

	response := &DeleteObjectsResponse{
		Errors:         make([]DeleteError, 0, len(toRemove)),
		DeletedObjects: make([]ObjectIdentifier, 0, len(toRemove)),
	}

	if errs := h.obj.DeleteObjects(r.Context(), bkt, toRemove); errs != nil && !requested.Quiet {
		h.log.Error("could not delete objects",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.Strings("object_name", toRemove),
			zap.Errors("errors", errs))

		for _, e := range errs {
			if err, ok := e.(*api.DeleteError); ok {
				code := "BadRequest"
				desc := err.Error()

				if st, ok := status.FromError(err.Err); ok && st != nil {
					desc = st.Message()
					code = st.Code().String()
				}

				response.Errors = append(response.Errors, DeleteError{
					Code:    code,
					Message: desc,
					Key:     err.Object,
				})

				delete(removed, err.Object)
			}
		}
	}

	for key := range removed {
		response.DeletedObjects = append(response.DeletedObjects, ObjectIdentifier{ObjectName: key})
	}

	if err := api.EncodeToResponse(w, response); err != nil {
		h.log.Error("could not write response",
			zap.String("request_id", rid),
			zap.String("bucket_name", bkt),
			zap.Strings("object_name", toRemove),
			zap.Error(err))

		api.WriteErrorResponse(r.Context(), w, api.Error{
			Code:           api.GetAPIError(api.ErrInternalError).Code,
			Description:    err.Error(),
			HTTPStatusCode: http.StatusInternalServerError,
		}, r.URL)
	}
}
