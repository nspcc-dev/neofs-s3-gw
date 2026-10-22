package api

import (
	"net/http"
	"net/url"
	"strings"
)

type (
	operation struct {
		name       string
		metric     string
		method     string
		objectPath bool // applies to /{bucket}/{object} requests
		bucketPath bool // applies to /{bucket} requests, and to object ones no object operation claimed
		// request conditions, all of which must hold
		query      string            // query parameter that must be present
		queryValue map[string]string // query parameters that must have these values
		header     string            // header that must be present
		uploadPart bool              // numeric partNumber together with uploadId
		formData   bool              // multipart/form-data body
		handler    func(Handler, http.ResponseWriter, *http.Request)
		unlimited  bool // served outside the max clients limiter
	}
)

const (
	listBucketsOperation = "ListBuckets"
)

var (
	operations = []operation{
		{
			name:       "Options",
			metric:     "preflight",
			method:     http.MethodOptions,
			objectPath: true,
			bucketPath: true,
			handler:    Handler.Preflight,
		},
		{
			name:       "HeadObject",
			metric:     "headobject",
			method:     http.MethodHead,
			objectPath: true,
			handler:    Handler.HeadObjectHandler,
		},
		{
			name:       "UploadPartCopy",
			metric:     "uploadpartcopy",
			method:     http.MethodPut,
			objectPath: true,
			header:     hdrAmzCopySource,
			uploadPart: true,
			handler:    Handler.UploadPartCopy,
		},
		{
			name:       "UploadPart",
			metric:     "uploadpart",
			method:     http.MethodPut,
			objectPath: true,
			uploadPart: true,
			handler:    Handler.UploadPartHandler,
		},
		{
			name:       "ListObjectParts",
			metric:     "listobjectparts",
			method:     http.MethodGet,
			objectPath: true,
			query:      "uploadId",
			handler:    Handler.ListPartsHandler,
		},
		{
			name:       "CompleteMultipartUpload",
			metric:     "completemutipartupload",
			method:     http.MethodPost,
			objectPath: true,
			query:      "uploadId",
			handler:    Handler.CompleteMultipartUploadHandler,
		},
		{
			name:       "CreateMultipartUpload",
			metric:     "createmultipartupload",
			method:     http.MethodPost,
			objectPath: true,
			query:      "uploads",
			handler:    Handler.CreateMultipartUploadHandler,
		},
		{
			name:       "AbortMultipartUpload",
			metric:     "abortmultipartupload",
			method:     http.MethodDelete,
			objectPath: true,
			query:      "uploadId",
			handler:    Handler.AbortMultipartUploadHandler,
		},
		{
			name:       "ListMultipartUploads",
			metric:     "listmultipartuploads",
			method:     http.MethodGet,
			objectPath: true,
			bucketPath: true,
			query:      "uploads",
			handler:    Handler.ListMultipartUploadsHandler,
		},
		{
			name:       "GetObjectACL",
			metric:     "getobjectacl",
			method:     http.MethodGet,
			objectPath: true,
			query:      "acl",
			handler:    Handler.GetObjectACLHandler,
		},
		{
			name:       "PutObjectACL",
			metric:     "putobjectacl",
			method:     http.MethodPut,
			objectPath: true,
			query:      "acl",
			handler:    Handler.PutObjectACLHandler,
		},
		{
			name:       "GetObjectTagging",
			metric:     "getobjecttagging",
			method:     http.MethodGet,
			objectPath: true,
			query:      "tagging",
			handler:    Handler.GetObjectTaggingHandler,
		},
		{
			name:       "PutObjectTagging",
			metric:     "putobjecttagging",
			method:     http.MethodPut,
			objectPath: true,
			query:      "tagging",
			handler:    Handler.PutObjectTaggingHandler,
		},
		{
			name:       "DeleteObjectTagging",
			metric:     "deleteobjecttagging",
			method:     http.MethodDelete,
			objectPath: true,
			query:      "tagging",
			handler:    Handler.DeleteObjectTaggingHandler,
		},
		{
			name:       "SelectObjectContent",
			metric:     "selectobjectcontent",
			method:     http.MethodPost,
			objectPath: true,
			query:      "select",
			queryValue: map[string]string{"select-type": "2"},
			handler:    Handler.SelectObjectContentHandler,
		},
		{
			name:       "GetObjectRetention",
			metric:     "getobjectretention",
			method:     http.MethodGet,
			objectPath: true,
			query:      "retention",
			handler:    Handler.GetObjectRetentionHandler,
		},
		{
			name:       "GetObjectLegalHold",
			metric:     "getobjectlegalhold",
			method:     http.MethodGet,
			objectPath: true,
			query:      "legal-hold",
			handler:    Handler.GetObjectLegalHoldHandler,
		},
		{
			name:       "GetObjectAttributes",
			metric:     "getobjectattributes",
			method:     http.MethodGet,
			objectPath: true,
			query:      "attributes",
			handler:    Handler.GetObjectAttributesHandler,
		},
		{
			name:       "GetObjectTorrent",
			metric:     "getobjecttorrent",
			method:     http.MethodGet,
			objectPath: true,
			query:      "torrent",
			handler:    Handler.GetObjectTorrentHandler,
		},
		{
			name:       "GetObject",
			metric:     "getobject",
			method:     http.MethodGet,
			objectPath: true,
			handler:    Handler.GetObjectHandler,
		},
		{
			name:       "CopyObject",
			metric:     "copyobject",
			method:     http.MethodPut,
			objectPath: true,
			header:     hdrAmzCopySource,
			handler:    Handler.CopyObjectHandler,
		},
		{
			name:       "PutObjectRetention",
			metric:     "putobjectretention",
			method:     http.MethodPut,
			objectPath: true,
			query:      "retention",
			handler:    Handler.PutObjectRetentionHandler,
		},
		{
			name:       "PutObjectLegalHold",
			metric:     "putobjectlegalhold",
			method:     http.MethodPut,
			objectPath: true,
			query:      "legal-hold",
			handler:    Handler.PutObjectLegalHoldHandler,
		},
		{
			name:       "PutObject",
			metric:     "putobject",
			method:     http.MethodPut,
			objectPath: true,
			handler:    Handler.PutObjectHandler,
		},
		{
			name:       "DeleteObject",
			metric:     "deleteobject",
			method:     http.MethodDelete,
			objectPath: true,
			handler:    Handler.DeleteObjectHandler,
		},
		{
			name:       "GetBucketLocation",
			metric:     "getbucketlocation",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "location",
			handler:    Handler.GetBucketLocationHandler,
		},
		{
			name:       "GetBucketPolicy",
			metric:     "getbucketpolicy",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "policy",
			handler:    Handler.GetBucketPolicyHandler,
		},
		{
			name:       "GetBucketLifecycle",
			metric:     "getbucketlifecycle",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "lifecycle",
			handler:    Handler.GetBucketLifecycleHandler,
		},
		{
			name:       "GetBucketEncryption",
			metric:     "getbucketencryption",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "encryption",
			handler:    Handler.GetBucketEncryptionHandler,
		},
		{
			name:       "GetBucketCors",
			metric:     "getbucketcors",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "cors",
			handler:    Handler.GetBucketCorsHandler,
		},
		{
			name:       "PutBucketCors",
			metric:     "putbucketcors",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "cors",
			handler:    Handler.PutBucketCorsHandler,
		},
		{
			name:       "DeleteBucketCors",
			metric:     "deletebucketcors",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "cors",
			handler:    Handler.DeleteBucketCorsHandler,
		},
		{
			name:       "GetBucketACL",
			metric:     "getbucketacl",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "acl",
			handler:    Handler.GetBucketACLHandler,
		},
		{
			name:       "PutBucketACL",
			metric:     "putbucketacl",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "acl",
			handler:    Handler.PutBucketACLHandler,
		},
		{
			name:       "GetBucketWebsite",
			metric:     "getbucketwebsite",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "website",
			handler:    Handler.GetBucketWebsiteHandler,
		},
		{
			name:       "GetBucketAccelerate",
			metric:     "getbucketaccelerate",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "accelerate",
			handler:    Handler.GetBucketAccelerateHandler,
		},
		{
			name:       "GetBucketRequestPayment",
			metric:     "getbucketrequestpayment",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "requestPayment",
			handler:    Handler.GetBucketRequestPaymentHandler,
		},
		{
			name:       "GetBucketLogging",
			metric:     "getbucketlogging",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "logging",
			handler:    Handler.GetBucketLoggingHandler,
		},
		{
			name:       "PutBucketLogging",
			metric:     "putbucketlogging",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "logging",
			handler:    Handler.PutBucketLoggingHandler,
		},
		{
			name:       "GetBucketReplication",
			metric:     "getbucketreplication",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "replication",
			handler:    Handler.GetBucketReplicationHandler,
		},
		{
			name:       "GetBucketTagging",
			metric:     "getbuckettagging",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "tagging",
			handler:    Handler.GetBucketTaggingHandler,
		},
		{
			name:       "DeleteBucketWebsite",
			metric:     "deletebucketwebsite",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "website",
			handler:    Handler.DeleteBucketWebsiteHandler,
		},
		{
			name:       "DeleteBucketTagging",
			metric:     "deletebuckettagging",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "tagging",
			handler:    Handler.DeleteBucketTaggingHandler,
		},
		{
			name:       "GetBucketObjectLockConfig",
			metric:     "getbucketobjectlockconfiguration",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "object-lock",
			handler:    Handler.GetBucketObjectLockConfigHandler,
		},
		{
			name:       "GetBucketVersioning",
			metric:     "getbucketversioning",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "versioning",
			handler:    Handler.GetBucketVersioningHandler,
		},
		{
			name:       "GetBucketNotification",
			metric:     "getbucketnotification",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "notification",
			handler:    Handler.GetBucketNotificationHandler,
		},
		{
			name:       "ListenBucketNotification",
			metric:     "listenbucketnotification",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "events",
			handler:    Handler.ListenBucketNotificationHandler,
			unlimited:  true,
		},
		{
			name:       "ListObjectsV2M",
			metric:     "listobjectsv2M",
			method:     http.MethodGet,
			bucketPath: true,
			queryValue: map[string]string{"list-type": "2", "metadata": "true"},
			handler:    Handler.ListObjectsV2MHandler,
		},
		{
			name:       "ListObjectsV2",
			metric:     "listobjectsv2",
			method:     http.MethodGet,
			bucketPath: true,
			queryValue: map[string]string{"list-type": "2"},
			handler:    Handler.ListObjectsV2Handler,
		},
		{
			name:       "ListBucketVersions",
			metric:     "listbucketversions",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "versions",
			handler:    Handler.ListBucketObjectVersionsHandler,
		},
		{
			name:       "GetBucketPolicyStatus",
			metric:     "getbucketpolicystatus",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "policyStatus",
			handler:    Handler.GetBucketPolicyStatusHandler,
		},
		{
			name:       "PutPublicAccessBlock",
			metric:     "putpublicaccessblock",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "publicAccessBlock",
			handler:    Handler.PutPublicAccessBlockHandler,
		},
		{
			name:       "GetPublicAccessBlock",
			metric:     "getpublicaccessblock",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "publicAccessBlock",
			handler:    Handler.GetPublicAccessBlockHandler,
		},
		{
			name:       "GetBucketOwnershipControls",
			metric:     "getbucketownershipcontrols",
			method:     http.MethodGet,
			bucketPath: true,
			query:      "ownershipControls",
			handler:    Handler.GetBucketOwnershipControlsHandler,
		},
		{
			name:       "ListObjectsV1",
			metric:     "listobjectsv1",
			method:     http.MethodGet,
			bucketPath: true,
			handler:    Handler.ListObjectsV1Handler,
		},
		{
			name:       "PutBucketLifecycle",
			metric:     "putbucketlifecycle",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "lifecycle",
			handler:    Handler.PutBucketLifecycleHandler,
		},
		{
			name:       "PutBucketEncryption",
			metric:     "putbucketencryption",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "encryption",
			handler:    Handler.PutBucketEncryptionHandler,
		},
		{
			name:       "PutBucketPolicy",
			metric:     "putbucketpolicy",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "policy",
			handler:    Handler.PutBucketPolicyHandler,
		},
		{
			name:       "PutBucketObjectLockConfig",
			metric:     "putbucketobjectlockconfig",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "object-lock",
			handler:    Handler.PutBucketObjectLockConfigHandler,
		},
		{
			name:       "PutBucketTagging",
			metric:     "putbuckettagging",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "tagging",
			handler:    Handler.PutBucketTaggingHandler,
		},
		{
			name:       "PutBucketVersioning",
			metric:     "putbucketversioning",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "versioning",
			handler:    Handler.PutBucketVersioningHandler,
		},
		{
			name:       "PutBucketNotification",
			metric:     "putbucketnotification",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "notification",
			handler:    Handler.PutBucketNotificationHandler,
		},
		{
			name:       "PutBucketOwnershipControls",
			metric:     "putbucketownershipcontrols",
			method:     http.MethodPut,
			bucketPath: true,
			query:      "ownershipControls",
			handler:    Handler.PutBucketOwnershipControlsHandler,
		},
		{
			name:       "DeleteBucketOwnershipControls",
			metric:     "deletebucketownershipcontrols",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "ownershipControls",
			handler:    Handler.DeleteBucketOwnershipControlsHandler,
		},
		{
			name:       "CreateBucket",
			metric:     "createbucket",
			method:     http.MethodPut,
			bucketPath: true,
			handler:    Handler.CreateBucketHandler,
		},
		{
			name:       "HeadBucket",
			metric:     "headbucket",
			method:     http.MethodHead,
			bucketPath: true,
			handler:    Handler.HeadBucketHandler,
		},
		{
			name:       "PostObject",
			metric:     "postobject",
			method:     http.MethodPost,
			objectPath: true,
			bucketPath: true,
			formData:   true,
			handler:    Handler.PostObject,
		},
		{
			name:       "DeleteMultipleObjects",
			metric:     "deletemultipleobjects",
			method:     http.MethodPost,
			objectPath: true,
			bucketPath: true,
			query:      "delete",
			handler:    Handler.DeleteMultipleObjectsHandler,
		},
		{
			name:       "DeleteBucketPolicy",
			metric:     "deletebucketpolicy",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "policy",
			handler:    Handler.DeleteBucketPolicyHandler,
		},
		{
			name:       "DeleteBucketLifecycle",
			metric:     "deletebucketlifecycle",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "lifecycle",
			handler:    Handler.DeleteBucketLifecycleHandler,
		},
		{
			name:       "DeleteBucketEncryption",
			metric:     "deletebucketencryption",
			method:     http.MethodDelete,
			bucketPath: true,
			query:      "encryption",
			handler:    Handler.DeleteBucketEncryptionHandler,
		},
		{
			name:       "DeleteBucket",
			metric:     "deletebucket",
			method:     http.MethodDelete,
			bucketPath: true,
			handler:    Handler.DeleteBucketHandler,
		},
	}
)

// matches reports whether the request conditions of op hold for the query and headers.
func (op *operation) matches(q url.Values, hdr http.Header) bool {
	if op.query != "" {
		if _, ok := q[op.query]; !ok {
			return false
		}
	}

	for key, value := range op.queryValue {
		if vals, ok := q[key]; !ok || vals[0] != value {
			return false
		}
	}

	if op.header != "" {
		if _, ok := hdr[op.header]; !ok {
			return false
		}
	}

	if op.uploadPart && !isUploadPart(q) {
		return false
	}

	if op.formData && !strings.Contains(hdr.Get(hdrContentType), "multipart/form-data") {
		return false
	}

	return true
}

// isUploadPart reports a numeric partNumber together with an uploadId.
func isUploadPart(q url.Values) bool {
	vals, ok := q["partNumber"]
	if !ok || vals[0] == "" {
		return false
	}

	for i := range len(vals[0]) {
		if vals[0][i] < '0' || vals[0][i] > '9' {
			return false
		}
	}

	_, ok = q["uploadId"]
	return ok
}

func resolveOperation(r *http.Request, hasObject bool) (name string, bucketOp bool) {
	var query = r.URL.Query()
	for i := range operations {
		var op = &operations[i]

		if op.method != r.Method || hasObject && !op.objectPath || !hasObject && !op.bucketPath {
			continue
		}

		if op.matches(query, r.Header) {
			return op.name, hasObject && op.bucketPath
		}
	}

	return "", false
}
