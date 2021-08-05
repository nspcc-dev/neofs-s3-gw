package handler

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-s3-gw/api"
)

// VersioningConfiguration contains VersioningConfiguration XML representation.
type VersioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	Text    string   `xml:",chardata"`
	Xmlns   string   `xml:"xmlns,attr"`
}

// ListMultipartUploadsResult contains ListMultipartUploadsResult XML representation.
type ListMultipartUploadsResult struct {
	XMLName xml.Name `xml:"ListMultipartUploadsResult"`
	Text    string   `xml:",chardata"`
	Xmlns   string   `xml:"xmlns,attr"`
}

const maxObjectList = 1000 // Limit number of objects in a listObjectsResponse/listObjectsVersionsResponse.

// ListBucketsHandler handles bucket listing requests.
func (h *handler) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		own     = owner.NewID()
		res     *ListBucketsResponse
		reqInfo = api.GetReqInfo(r.Context())
	)

	list, err := h.obj.ListBuckets(r.Context())
	if err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}

	if len(list) > 0 {
		own = list[0].Owner
	}

	res = &ListBucketsResponse{
		Owner: Owner{
			ID:          own.String(),
			DisplayName: own.String(),
		},
	}

	for _, item := range list {
		res.Buckets.Buckets = append(res.Buckets.Buckets, Bucket{
			Name:         item.Name,
			CreationDate: item.Created.Format(time.RFC3339),
		})
	}

	if err = api.EncodeToResponse(w, res); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

// GetBucketVersioningHandler implements bucket versioning getter handler.
func (h *handler) GetBucketVersioningHandler(w http.ResponseWriter, r *http.Request) {
	var (
		reqInfo = api.GetReqInfo(r.Context())
		res     = new(VersioningConfiguration)
	)

	res.Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

	if err := api.EncodeToResponse(w, res); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

// ListMultipartUploadsHandler implements multipart uploads listing handler.
func (h *handler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		reqInfo = api.GetReqInfo(r.Context())
		res     = new(ListMultipartUploadsResult)
	)

	res.Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

	if err := api.EncodeToResponse(w, res); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}
