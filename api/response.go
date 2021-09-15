package api

import (
	"encoding/xml"
	"fmt"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
)

type (
	// ErrorResponse - error response format.
	ErrorResponse struct {
		XMLName    xml.Name `xml:"Error" json:"-"`
		Code       string
		Message    string
		Key        string `xml:"Key,omitempty" json:"Key,omitempty"`
		BucketName string `xml:"BucketName,omitempty" json:"BucketName,omitempty"`
		Resource   string
		RequestID  string `xml:"RequestId" json:"RequestId"`
		HostID     string `xml:"HostId" json:"HostId"`

		// Region where the bucket is located. This header is returned
		// only in HEAD bucket and ListObjects response.
		Region string `xml:"Region,omitempty" json:"Region,omitempty"`

		// Captures the server string returned in response header.
		Server string `xml:"-" json:"-"`

		// Underlying HTTP status code for the returned error.
		StatusCode int `xml:"-" json:"-"`
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

var (
	deploymentID, _ = uuid.NewRandom()

	xmlHeader = []byte(xml.Header)
)

// Non exhaustive list of AWS S3 standard error responses -
// http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
var s3ErrorResponseMap = map[string]string{
	"AccessDenied":                      "Access Denied.",
	"BadDigest":                         "The Content-Md5 you specified did not match what we received.",
	"EntityTooSmall":                    "Your proposed upload is smaller than the minimum allowed object size.",
	"EntityTooLarge":                    "Your proposed upload exceeds the maximum allowed object size.",
	"IncompleteBody":                    "You did not provide the number of bytes specified by the Content-Length HTTP header.",
	"InternalError":                     "We encountered an internal error, please try again.",
	"InvalidAccessKeyId":                "The access key ID you provided does not exist in our records.",
	"InvalidBucketName":                 "The specified bucket is not valid.",
	"InvalidDigest":                     "The Content-Md5 you specified is not valid.",
	"InvalidRange":                      "The requested range is not satisfiable",
	"MalformedXML":                      "The XML you provided was not well-formed or did not validate against our published schema.",
	"MissingContentLength":              "You must provide the Content-Length HTTP header.",
	"MissingContentMD5":                 "Missing required header for this request: Content-Md5.",
	"MissingRequestBodyError":           "Request body is empty.",
	"NoSuchBucket":                      "The specified bucket does not exist.",
	"NoSuchBucketPolicy":                "The bucket policy does not exist",
	"NoSuchKey":                         "The specified key does not exist.",
	"NoSuchUpload":                      "The specified multipart upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.",
	"NotImplemented":                    "A header you provided implies functionality that is not implemented",
	"PreconditionFailed":                "At least one of the pre-conditions you specified did not hold",
	"RequestTimeTooSkewed":              "The difference between the request time and the server's time is too large.",
	"SignatureDoesNotMatch":             "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
	"MethodNotAllowed":                  "The specified method is not allowed against this resource.",
	"InvalidPart":                       "One or more of the specified parts could not be found.",
	"InvalidPartOrder":                  "The list of parts was not in ascending order. The parts list must be specified in order by part number.",
	"InvalidObjectState":                "The operation is not valid for the current state of the object.",
	"AuthorizationHeaderMalformed":      "The authorization header is malformed; the region is wrong.",
	"MalformedPOSTRequest":              "The body of your POST request is not well-formed multipart/form-data.",
	"BucketNotEmpty":                    "The bucket you tried to delete is not empty",
	"AllAccessDisabled":                 "All access to this bucket has been disabled.",
	"MalformedPolicy":                   "Policy has invalid resource.",
	"MissingFields":                     "Missing fields in request.",
	"AuthorizationQueryParametersError": "Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".",
	"MalformedDate":                     "Invalid date format header, expected to be in ISO8601, RFC1123 or RFC1123Z time format.",
	"BucketAlreadyOwnedByYou":           "Your previous request to create the named bucket succeeded and you already own it.",
	"InvalidDuration":                   "Duration provided in the request is invalid.",
	"XAmzContentSHA256Mismatch":         "The provided 'x-amz-content-sha256' header does not match what was computed.",
	// Add new API errors here.
}

// Error - Returns S3 error string.
func (e ErrorResponse) Error() string {
	if e.Message == "" {
		msg, ok := s3ErrorResponseMap[e.Code]
		if !ok {
			msg = fmt.Sprintf("Error response code %s.", e.Code)
		}
		return msg
	}
	return e.Message
}

// getErrorResponse gets in standard error and resource value and
// provides a encodable populated response values.
func getAPIErrorResponse(info *ReqInfo, err error) ErrorResponse {
	code := "InternalError"
	desc := err.Error()

	if e, ok := err.(errors.Error); ok {
		code = e.Code
		desc = e.Description
	}

	return ErrorResponse{
		Code:       code,
		Message:    desc,
		BucketName: info.BucketName,
		Key:        info.ObjectName,
		Resource:   info.URL.Path,
		RequestID:  info.RequestID,
		HostID:     info.DeploymentID,
	}
}
