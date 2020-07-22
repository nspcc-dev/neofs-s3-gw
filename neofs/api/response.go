package api

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/google/uuid"
	"github.com/minio/minio/misc"
)

type (
	// APIErrorResponse - error response format
	ErrorResponse struct {
		XMLName    xml.Name `xml:"Error" json:"-"`
		Code       string
		Message    string
		Key        string `xml:"Key,omitempty" json:"Key,omitempty"`
		BucketName string `xml:"BucketName,omitempty" json:"BucketName,omitempty"`
		Resource   string
		Region     string `xml:"Region,omitempty" json:"Region,omitempty"`
		RequestID  string `xml:"RequestId" json:"RequestId"`
		HostID     string `xml:"HostId" json:"HostId"`
	}

	// APIError structure
	Error struct {
		Code           string
		Description    string
		HTTPStatusCode int
	}
)

const (
	hdrServerInfo    = "Server"
	hdrAcceptRanges  = "Accept-Ranges"
	hdrContentType   = "Content-Type"
	hdrContentLength = "Content-Length"
	hdrRetryAfter    = "Retry-After"

	hdrAmzCopySource = "X-Amz-Copy-Source"

	// Response request id.
	hdrAmzRequestID = "x-amz-request-id"

	// hdrSSE is the general AWS SSE HTTP header key.
	hdrSSE = "X-Amz-Server-Side-Encryption"

	// hdrSSECustomerKey is the HTTP header key referencing the
	// SSE-C client-provided key..
	hdrSSECustomerKey = hdrSSE + "-Customer-Key"

	// hdrSSECopyKey is the HTTP header key referencing the SSE-C
	// client-provided key for SSE-C copy requests.
	hdrSSECopyKey = "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key"
)

var deploymentID, _ = uuid.NewRandom()

// WriteErrorResponse writes error headers
func WriteErrorResponse(ctx context.Context, w http.ResponseWriter, err Error, reqURL *url.URL) {
	switch err.Code {
	case "SlowDown", "XNeoFSServerNotInitialized", "XNeoFSReadQuorum", "XNeoFSWriteQuorum":
		// Set retry-after header to indicate user-agents to retry request after 120secs.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
		w.Header().Set(hdrRetryAfter, "120")
	case "AccessDenied":
		// TODO process when the request is from browser and also if browser
	}

	// Generate error response.
	errorResponse := getAPIErrorResponse(ctx, err, reqURL.Path,
		w.Header().Get(hdrAmzRequestID), deploymentID.String())
	encodedErrorResponse := encodeResponse(errorResponse)
	writeResponse(w, err.HTTPStatusCode, encodedErrorResponse, mimeXML)
}

// If none of the http routes match respond with appropriate errors
func errorResponseHandler(w http.ResponseWriter, r *http.Request) {
	desc := fmt.Sprintf("Unknown API request at %s", r.URL.Path)
	WriteErrorResponse(r.Context(), w, Error{
		Code:           "XMinioUnknownAPIRequest",
		Description:    desc,
		HTTPStatusCode: http.StatusBadRequest,
	}, r.URL)
}

// Write http common headers
func setCommonHeaders(w http.ResponseWriter) {
	w.Header().Set(hdrServerInfo, "NeoFS-S3-Gate/"+misc.Version)
	w.Header().Set(hdrAcceptRanges, "bytes")

	// Remove sensitive information
	removeSensitiveHeaders(w.Header())
}

// removeSensitiveHeaders removes confidential encryption
// information - e.g. the SSE-C key - from the HTTP headers.
// It has the same semantics as RemoveSensitiveEntires.
func removeSensitiveHeaders(h http.Header) {
	h.Del(hdrSSECustomerKey)
	h.Del(hdrSSECopyKey)
}

func writeResponse(w http.ResponseWriter, statusCode int, response []byte, mType mimeType) {
	setCommonHeaders(w)
	if mType != mimeNone {
		w.Header().Set(hdrContentType, string(mType))
	}
	w.Header().Set(hdrContentLength, strconv.Itoa(len(response)))
	w.WriteHeader(statusCode)
	if response != nil {
		_, _ = w.Write(response)
		w.(http.Flusher).Flush()
	}
}

// Encodes the response headers into XML format.
func encodeResponse(response interface{}) []byte {
	var bytesBuffer bytes.Buffer
	bytesBuffer.WriteString(xml.Header)
	_ = xml.
		NewEncoder(&bytesBuffer).
		Encode(response)
	return bytesBuffer.Bytes()
}
