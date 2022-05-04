package handler

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

type (
	InitiateMultipartUploadResponse struct {
		XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult" json:"-"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}

	CompleteMultipartUploadResponse struct {
		XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult" json:"-"`
		Bucket  string   `xml:"Bucket"`
		Key     string   `xml:"Key"`
		ETag    string   `xml:"ETag"`
	}

	ListMultipartUploadsResponse struct {
		XMLName            xml.Name          `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult" json:"-"`
		Bucket             string            `xml:"Bucket"`
		CommonPrefixes     []CommonPrefix    `xml:"CommonPrefixes"`
		Delimiter          string            `xml:"Delimiter,omitempty"`
		EncodingType       string            `xml:"EncodingType,omitempty"`
		IsTruncated        bool              `xml:"IsTruncated"`
		KeyMarker          string            `xml:"KeyMarker"`
		MaxUploads         int               `xml:"MaxUploads"`
		NextKeyMarker      string            `xml:"NextKeyMarker,omitempty"`
		NextUploadIDMarker string            `xml:"NextUploadIdMarker,omitempty"`
		Prefix             string            `xml:"Prefix"`
		Uploads            []MultipartUpload `xml:"Upload"`
		UploadIDMarker     string            `xml:"UploadIdMarker,omitempty"`
	}

	ListPartsResponse struct {
		XMLName              xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult" json:"-"`
		Bucket               string        `xml:"Bucket"`
		Initiator            Initiator     `xml:"Initiator"`
		IsTruncated          bool          `xml:"IsTruncated"`
		Key                  string        `xml:"Key"`
		MaxParts             int           `xml:"MaxParts,omitempty"`
		NextPartNumberMarker int           `xml:"NextPartNumberMarker,omitempty"`
		Owner                Owner         `xml:"Owner"`
		Parts                []*layer.Part `xml:"Part"`
		PartNumberMarker     int           `xml:"PartNumberMarker,omitempty"`
		StorageClass         string        `xml:"StorageClass,omitempty"`
		UploadID             string        `xml:"UploadId"`
	}

	MultipartUpload struct {
		Initiated    string    `xml:"Initiated"`
		Initiator    Initiator `xml:"Initiator"`
		Key          string    `xml:"Key"`
		Owner        Owner     `xml:"Owner"`
		StorageClass string    `xml:"StorageClass,omitempty"`
		UploadID     string    `xml:"UploadId"`
	}

	Initiator struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	}

	CompleteMultipartUpload struct {
		XMLName xml.Name               `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUpload"`
		Parts   []*layer.CompletedPart `xml:"Part"`
	}

	UploadPartCopyResponse struct {
		ETag         string `xml:"ETag"`
		LastModified string `xml:"LastModified"`
	}

	UploadData struct {
		TagSet map[string]string
		ACL    *AccessControlPolicy
	}
)

const (
	uploadIDHeaderName   = "uploadId"
	partNumberHeaderName = "partNumber"
)

func (h *handler) CreateMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	/* initiation of multipart uploads is implemented via creation of "system" upload part with 0 part number
	(min value of partNumber of a common part is 1) and holding data: metadata, acl, tagging */
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var (
		hasData bool
		b       []byte

		uploadID   = uuid.New()
		data       = &UploadData{}
		additional = []zap.Field{
			zap.String("uploadID", uploadID.String()),
			zap.String("Key", reqInfo.ObjectName),
		}
		uploadInfo = &layer.UploadInfoParams{
			UploadID: uploadID.String(),
			Bkt:      bktInfo,
			Key:      reqInfo.ObjectName,
		}
	)

	if containsACLHeaders(r) {
		key, err := h.bearerTokenIssuerKey(r.Context())
		if err != nil {
			h.logAndSendError(w, "couldn't get gate key", reqInfo, err)
			return
		}
		data.ACL, err = parseACLHeaders(r.Header, key)
		if err != nil {
			h.logAndSendError(w, "could not parse acl", reqInfo, err)
			return
		}
		hasData = true
	}

	if len(r.Header.Get(api.AmzTagging)) > 0 {
		data.TagSet, err = parseTaggingHeader(r.Header)
		if err != nil {
			h.logAndSendError(w, "could not parse tagging", reqInfo, err, additional...)
			return
		}
		hasData = true
	}

	metadata := parseMetadata(r)
	if contentType := r.Header.Get(api.ContentType); len(contentType) > 0 {
		metadata[api.ContentType] = contentType
	}

	p := &layer.UploadPartParams{
		Info:       uploadInfo,
		PartNumber: 0,
		Header:     metadata,
	}

	if hasData {
		b, err = json.Marshal(data)
		if err != nil {
			h.logAndSendError(w, "could not marshal json with acl and/or tagging", reqInfo, err, additional...)
			return
		}
		p.Reader = bytes.NewReader(b)
	}

	info, err := h.obj.UploadPart(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not upload a part", reqInfo, err, additional...)
		return
	}

	resp := InitiateMultipartUploadResponse{
		Bucket:   info.Bucket,
		Key:      info.Headers[layer.UploadKeyAttributeName],
		UploadID: info.Headers[layer.UploadIDAttributeName],
	}

	if err := api.EncodeToResponse(w, resp); err != nil {
		h.logAndSendError(w, "could not encode InitiateMultipartUploadResponse to response", reqInfo, err, additional...)
		return
	}
}

func (h *handler) UploadPartHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var (
		queryValues = r.URL.Query()
		uploadID    = queryValues.Get(uploadIDHeaderName)
		additional  = []zap.Field{zap.String("uploadID", uploadID), zap.String("Key", reqInfo.ObjectName)}
	)

	partNumber, err := strconv.Atoi(queryValues.Get(partNumberHeaderName))
	if err != nil || partNumber < layer.UploadMinPartNumber || partNumber > layer.UploadMaxPartNumber {
		h.logAndSendError(w, "invalid part number", reqInfo, errors.GetAPIError(errors.ErrInvalidPartNumber))
		return
	}

	p := &layer.UploadPartParams{
		Info: &layer.UploadInfoParams{
			UploadID: uploadID,
			Bkt:      bktInfo,
			Key:      reqInfo.ObjectName,
		},
		PartNumber: partNumber,
		Size:       r.ContentLength,
		Reader:     r.Body,
	}

	info, err := h.obj.UploadPart(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not upload a part", reqInfo, err, additional...)
		return
	}

	w.Header().Set(api.ETag, info.HashSum)
	api.WriteSuccessResponseHeadersOnly(w)
}

func (h *handler) UploadPartCopy(w http.ResponseWriter, r *http.Request) {
	var (
		versionID   string
		reqInfo     = api.GetReqInfo(r.Context())
		queryValues = reqInfo.URL.Query()
		uploadID    = queryValues.Get(uploadIDHeaderName)
		additional  = []zap.Field{zap.String("uploadID", uploadID), zap.String("Key", reqInfo.ObjectName)}
	)

	partNumber, err := strconv.Atoi(queryValues.Get(partNumberHeaderName))
	if err != nil || partNumber < layer.UploadMinPartNumber || partNumber > layer.UploadMaxPartNumber {
		h.logAndSendError(w, "invalid part number", reqInfo, errors.GetAPIError(errors.ErrInvalidPartNumber))
		return
	}

	src := r.Header.Get(api.AmzCopySource)
	if u, err := url.Parse(src); err == nil {
		versionID = u.Query().Get(api.QueryVersionID)
		src = u.Path
	}
	srcBucket, srcObject := path2BucketObject(src)

	srcRange, err := parseRange(r.Header.Get(api.AmzCopySourceRange))
	if err != nil {
		h.logAndSendError(w, "could not parse copy range", reqInfo,
			errors.GetAPIError(errors.ErrInvalidCopyPartRange), additional...)
		return
	}

	srcBktInfo, err := h.getBucketAndCheckOwner(r, srcBucket, api.AmzSourceExpectedBucketOwner)
	if err != nil {
		h.logAndSendError(w, "could not get source bucket info", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get target bucket info", reqInfo, err)
		return
	}

	srcInfo, err := h.obj.GetObjectInfo(r.Context(), &layer.HeadObjectParams{
		BktInfo:   srcBktInfo,
		Object:    srcObject,
		VersionID: versionID,
	})
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchKey) && versionID != "" {
			h.logAndSendError(w, "could not head source object version", reqInfo,
				errors.GetAPIError(errors.ErrBadRequest), additional...)
			return
		}
		h.logAndSendError(w, "could not head source object", reqInfo, err, additional...)
		return
	}
	if isDeleted(srcInfo) {
		if versionID != "" {
			h.logAndSendError(w, "could not head source object version", reqInfo,
				errors.GetAPIError(errors.ErrBadRequest), additional...)
			return
		}
		h.logAndSendError(w, "could not head source object", reqInfo,
			errors.GetAPIError(errors.ErrNoSuchKey), additional...)
		return
	}

	args, err := parseCopyObjectArgs(r.Header)
	if err != nil {
		h.logAndSendError(w, "could not parse copy object args", reqInfo,
			errors.GetAPIError(errors.ErrInvalidCopyPartRange), additional...)
		return
	}

	if err = checkPreconditions(srcInfo, args.Conditional); err != nil {
		h.logAndSendError(w, "precondition failed", reqInfo, errors.GetAPIError(errors.ErrPreconditionFailed),
			additional...)
		return
	}

	p := &layer.UploadCopyParams{
		Info: &layer.UploadInfoParams{
			UploadID: uploadID,
			Bkt:      bktInfo,
			Key:      reqInfo.ObjectName,
		},
		SrcObjInfo: srcInfo,
		PartNumber: partNumber,
		Range:      srcRange,
	}

	info, err := h.obj.UploadPartCopy(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not upload part copy", reqInfo, err, additional...)
		return
	}

	response := UploadPartCopyResponse{
		ETag:         info.HashSum,
		LastModified: info.Created.UTC().Format(time.RFC3339),
	}

	if err = api.EncodeToResponse(w, response); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) CompleteMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var (
		sessionTokenSetEACL *session.Container

		uploadID   = r.URL.Query().Get(uploadIDHeaderName)
		uploadInfo = &layer.UploadInfoParams{
			UploadID: uploadID,
			Bkt:      bktInfo,
			Key:      reqInfo.ObjectName,
		}
		additional = []zap.Field{zap.String("uploadID", uploadID), zap.String("Key", reqInfo.ObjectName)}
		uploadData = &UploadData{}
	)

	reqBody := new(CompleteMultipartUpload)
	if err := xml.NewDecoder(r.Body).Decode(reqBody); err != nil {
		h.logAndSendError(w, "could not read complete multipart upload xml", reqInfo,
			errors.GetAPIError(errors.ErrMalformedXML), additional...)
		return
	}
	if len(reqBody.Parts) == 0 {
		h.logAndSendError(w, "invalid xml with parts", reqInfo, errors.GetAPIError(errors.ErrMalformedXML), additional...)
		return
	}

	initPart, err := h.obj.GetUploadInitInfo(r.Context(), uploadInfo)
	if err != nil {
		h.logAndSendError(w, "could not get multipart upload info", reqInfo, err, additional...)
		return
	}

	if initPart.Size > 0 {
		initPartPayload := bytes.NewBuffer(make([]byte, 0, initPart.Size))
		p := &layer.GetObjectParams{
			ObjectInfo: initPart,
			Writer:     initPartPayload,
		}
		if err = h.obj.GetObject(r.Context(), p); err != nil {
			h.logAndSendError(w, "could not get multipart upload acl and/or tagging", reqInfo, err, additional...)
			return
		}

		if err = json.Unmarshal(initPartPayload.Bytes(), uploadData); err != nil {
			h.logAndSendError(w, "could not unmarshal multipart upload acl and/or tagging", reqInfo, err, additional...)
			return
		}

		if uploadData.ACL != nil {
			if sessionTokenSetEACL, err = getSessionTokenSetEACL(r.Context()); err != nil {
				h.logAndSendError(w, "couldn't get eacl token", reqInfo, err)
				return
			}
		}
	}

	c := &layer.CompleteMultipartParams{
		Info:  uploadInfo,
		Parts: reqBody.Parts,
	}
	objInfo, err := h.obj.CompleteMultipartUpload(r.Context(), c)
	if err != nil {
		h.logAndSendError(w, "could not complete multipart upload", reqInfo, err, additional...)
		return
	}

	if len(uploadData.TagSet) != 0 {
		t := &layer.PutTaggingParams{
			ObjectInfo: objInfo,
			TagSet:     uploadData.TagSet,
		}
		if err = h.obj.PutObjectTagging(r.Context(), t); err != nil {
			h.logAndSendError(w, "could not put tagging file of completed multipart upload", reqInfo, err, additional...)
			return
		}
	}

	if uploadData.ACL != nil {
		resInfo := &resourceInfo{
			Bucket: objInfo.Bucket,
			Object: objInfo.Name,
		}
		astObject, err := aclToAst(uploadData.ACL, resInfo)
		if err != nil {
			h.logAndSendError(w, "could not translate acl of completed multipart upload to ast", reqInfo, err, additional...)
			return
		}
		if err = h.updateBucketACL(r, astObject, bktInfo, sessionTokenSetEACL); err != nil {
			h.logAndSendError(w, "could not update bucket acl while completing multipart upload", reqInfo, err, additional...)
			return
		}
	}

	s := &SendNotificationParams{
		Event:   EventObjectCreatedCompleteMultipartUpload,
		ObjInfo: objInfo,
		BktInfo: bktInfo,
		ReqInfo: reqInfo,
	}
	if err = h.sendNotifications(r.Context(), s); err != nil {
		h.log.Error("couldn't send notification: %w", zap.Error(err))
	}

	bktSettings, err := h.obj.GetBucketSettings(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get bucket settings", reqInfo, err)
	}

	if err = h.obj.DeleteSystemObject(r.Context(), bktInfo, layer.FormUploadPartName(uploadID, uploadInfo.Key, 0)); err != nil {
		h.logAndSendError(w, "could not delete init file of multipart upload", reqInfo, err, additional...)
		return
	}

	response := CompleteMultipartUploadResponse{
		Bucket: objInfo.Bucket,
		ETag:   objInfo.HashSum,
		Key:    objInfo.Name,
	}

	if bktSettings.VersioningEnabled {
		w.Header().Set(api.AmzVersionID, objInfo.Version())
	}

	if err = api.EncodeToResponse(w, response); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) ListMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var (
		queryValues = reqInfo.URL.Query()
		delimiter   = queryValues.Get("delimiter")
		prefix      = queryValues.Get("prefix")
		maxUploads  = layer.MaxSizeUploadsList
	)

	if queryValues.Get("max-uploads") != "" {
		val, err := strconv.Atoi(queryValues.Get("max-uploads"))
		if err != nil || val < 0 {
			h.logAndSendError(w, "invalid maxUploads", reqInfo, errors.GetAPIError(errors.ErrInvalidMaxUploads))
			return
		}
		if val < maxUploads {
			maxUploads = val
		}
	}

	p := &layer.ListMultipartUploadsParams{
		Bkt:            bktInfo,
		Delimiter:      delimiter,
		EncodingType:   queryValues.Get("encoding-type"),
		KeyMarker:      queryValues.Get("key-marker"),
		MaxUploads:     maxUploads,
		Prefix:         prefix,
		UploadIDMarker: queryValues.Get("upload-id-marker"),
	}

	list, err := h.obj.ListMultipartUploads(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not list multipart uploads", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, encodeListMultipartUploadsToResponse(list, p)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) ListPartsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var (
		partNumberMarker int

		queryValues = reqInfo.URL.Query()
		uploadID    = queryValues.Get(uploadIDHeaderName)
		additional  = []zap.Field{zap.String("uploadID", uploadID), zap.String("Key", reqInfo.ObjectName)}
		maxParts    = layer.MaxSizePartsList
	)

	if queryValues.Get("max-parts") != "" {
		val, err := strconv.Atoi(queryValues.Get("max-parts"))
		if err != nil || val < 0 {
			h.logAndSendError(w, "invalid MaxParts", reqInfo, errors.GetAPIError(errors.ErrInvalidMaxParts), additional...)
			return
		}
		if val < layer.MaxSizePartsList {
			maxParts = val
		}
	}

	if queryValues.Get("part-number-marker") != "" {
		if partNumberMarker, err = strconv.Atoi(queryValues.Get("part-number-marker")); err != nil || partNumberMarker <= 0 {
			h.logAndSendError(w, "invalid PartNumberMarker", reqInfo, err, additional...)
			return
		}
	}

	p := &layer.ListPartsParams{
		Info: &layer.UploadInfoParams{
			UploadID: uploadID,
			Bkt:      bktInfo,
			Key:      reqInfo.ObjectName,
		},
		MaxParts:         maxParts,
		PartNumberMarker: partNumberMarker,
	}

	list, err := h.obj.ListParts(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not list parts", reqInfo, err, additional...)
		return
	}

	if err = api.EncodeToResponse(w, encodeListPartsToResponse(list, p)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) AbortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	var (
		queryValues = reqInfo.URL.Query()
		uploadID    = queryValues.Get(uploadIDHeaderName)
		additional  = []zap.Field{zap.String("uploadID", uploadID), zap.String("Key", reqInfo.ObjectName)}

		p = &layer.UploadInfoParams{
			UploadID: uploadID,
			Bkt:      bktInfo,
			Key:      reqInfo.ObjectName,
		}
	)

	if err := h.obj.AbortMultipartUpload(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not abort multipart upload", reqInfo, err, additional...)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func encodeListMultipartUploadsToResponse(info *layer.ListMultipartUploadsInfo, params *layer.ListMultipartUploadsParams) *ListMultipartUploadsResponse {
	res := ListMultipartUploadsResponse{
		Bucket:             params.Bkt.Name,
		CommonPrefixes:     fillPrefixes(info.Prefixes, params.EncodingType),
		Delimiter:          params.Delimiter,
		EncodingType:       params.EncodingType,
		IsTruncated:        info.IsTruncated,
		KeyMarker:          params.KeyMarker,
		MaxUploads:         params.MaxUploads,
		NextKeyMarker:      info.NextKeyMarker,
		NextUploadIDMarker: info.NextUploadIDMarker,
		Prefix:             params.Prefix,
		UploadIDMarker:     params.UploadIDMarker,
	}

	uploads := make([]MultipartUpload, 0, len(info.Uploads))
	for _, u := range info.Uploads {
		m := MultipartUpload{
			Initiated: u.Created.UTC().Format(time.RFC3339),
			Initiator: Initiator{
				ID:          u.Owner.String(),
				DisplayName: u.Owner.String(),
			},
			Key: u.Key,
			Owner: Owner{
				ID:          u.Owner.String(),
				DisplayName: u.Owner.String(),
			},
			UploadID: u.UploadID,
		}
		uploads = append(uploads, m)
	}

	res.Uploads = uploads

	return &res
}

func encodeListPartsToResponse(info *layer.ListPartsInfo, params *layer.ListPartsParams) *ListPartsResponse {
	return &ListPartsResponse{
		XMLName: xml.Name{},
		Bucket:  params.Info.Bkt.Name,
		Initiator: Initiator{
			ID:          info.Owner.String(),
			DisplayName: info.Owner.String(),
		},
		IsTruncated:          info.IsTruncated,
		Key:                  params.Info.Key,
		MaxParts:             params.MaxParts,
		NextPartNumberMarker: info.NextPartNumberMarker,
		Owner: Owner{
			ID:          info.Owner.String(),
			DisplayName: info.Owner.String(),
		},
		PartNumberMarker: params.PartNumberMarker,
		UploadID:         params.Info.UploadID,
		Parts:            info.Parts,
	}
}

func isDeleted(objInfo *data.ObjectInfo) bool {
	return objInfo.Headers[layer.VersionsDeleteMarkAttr] == layer.DelMarkFullObject
}
