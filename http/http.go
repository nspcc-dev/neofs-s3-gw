package http

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/minio/minio/legacy/crypto"
)

type (
	HTTPResponseWriter struct {
		serverName   string
		serverRegion string
	}

	// MimeType represents various MIME type used API responses.
	MimeType string

	// ContextKey is a custom type used to pass values within contexts.
	ContextKey string
)

const BearerTokenContextKey ContextKey = "bearer-token"

const (
	// MimeType_None means no response type.
	MimeType_None MimeType = ""
	// MimeType_ApplicationJSON means response type is JSON.
	MimeType_ApplicationJSON MimeType = "application/json"
	// MimeType_ApplicationXML means response type is XML.
	MimeType_ApplicationXML MimeType = "application/xml"
)

func NewHTTPResponseWriter(appName, appVersion, region string) *HTTPResponseWriter {
	return &HTTPResponseWriter{
		serverName:   fmt.Sprintf("%s/%s", appName, appVersion),
		serverRegion: region,
	}
}

func (rw *HTTPResponseWriter) writeResponse(w http.ResponseWriter, statusCode int, response []byte, mimeType MimeType) {
	w.Header().Set("Server", rw.serverName)
	if len(rw.serverRegion) > 0 {
		w.Header().Set("X-Amz-Bucket-Region", rw.serverRegion)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	crypto.RemoveSensitiveHeaders(w.Header())
	if mimeType != MimeType_None {
		w.Header().Set("Content-Type", string(mimeType))
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.WriteHeader(statusCode)
	if response != nil {
		w.Write(response)
		w.(http.Flusher).Flush()
	}
}
