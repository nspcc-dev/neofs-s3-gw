package handler

import (
	"encoding/xml"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

const (
	allowedTagChars = "+-=._:/@"

	maxTags           = 10
	keyTagMaxLength   = 128
	valueTagMaxLength = 256
)

func (h *handler) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	tagSet, err := readTagSet(r.Body)
	if err != nil {
		h.logAndSendError(w, "could not read tag set", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	p2 := &layer.PutTaggingParams{
		ObjectInfo: objInfo,
		TagSet:     tagSet,
	}

	if err = h.obj.PutObjectTagging(r.Context(), p2); err != nil {
		h.logAndSendError(w, "could not put object tagging", reqInfo, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *handler) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	tagSet, err := h.obj.GetObjectTagging(r.Context(), objInfo)
	if err != nil {
		h.logAndSendError(w, "could not get object tagging", reqInfo, err)
		return
	}

	w.Header().Set(api.AmzVersionID, objInfo.Version())
	if err = api.EncodeToResponse(w, encodeTagging(tagSet)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func (h *handler) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		BktInfo:   bktInfo,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	if err = h.obj.DeleteObjectTagging(r.Context(), bktInfo, objInfo); err != nil {
		h.logAndSendError(w, "could not delete object tagging", reqInfo, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) PutBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	tagSet, err := readTagSet(r.Body)
	if err != nil {
		h.logAndSendError(w, "could not read tag set", reqInfo, err)
		return
	}

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = h.obj.PutBucketTagging(r.Context(), bktInfo, tagSet); err != nil {
		h.logAndSendError(w, "could not put object tagging", reqInfo, err)
		return
	}
}

func (h *handler) GetBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	tagSet, err := h.obj.GetBucketTagging(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get object tagging", reqInfo, err)
		return
	}

	if err = api.EncodeToResponse(w, encodeTagging(tagSet)); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
		return
	}
}

func (h *handler) DeleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.getBucketAndCheckOwner(r, reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = h.obj.DeleteBucketTagging(r.Context(), bktInfo); err != nil {
		h.logAndSendError(w, "could not delete bucket tagging", reqInfo, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func readTagSet(reader io.Reader) (map[string]string, error) {
	tagging := new(Tagging)
	if err := xml.NewDecoder(reader).Decode(tagging); err != nil {
		return nil, errors.GetAPIError(errors.ErrMalformedXML)
	}

	if err := checkTagSet(tagging.TagSet); err != nil {
		return nil, err
	}

	tagSet := make(map[string]string, len(tagging.TagSet))
	for _, tag := range tagging.TagSet {
		tagSet[tag.Key] = tag.Value
	}

	return tagSet, nil
}

func encodeTagging(tagSet map[string]string) *Tagging {
	tagging := &Tagging{}
	for k, v := range tagSet {
		tagging.TagSet = append(tagging.TagSet, Tag{Key: k, Value: v})
	}
	sort.Slice(tagging.TagSet, func(i, j int) bool {
		return tagging.TagSet[i].Key < tagging.TagSet[j].Key
	})

	return tagging
}

func checkTagSet(tagSet []Tag) error {
	if len(tagSet) > maxTags {
		return errors.GetAPIError(errors.ErrInvalidTagsSizeExceed)
	}

	for _, tag := range tagSet {
		if err := checkTag(tag); err != nil {
			return err
		}
	}

	return nil
}

func checkTag(tag Tag) error {
	if len(tag.Key) < 1 || len(tag.Key) > keyTagMaxLength {
		return errors.GetAPIError(errors.ErrInvalidTagKey)
	}
	if len(tag.Value) > valueTagMaxLength {
		return errors.GetAPIError(errors.ErrInvalidTagValue)
	}

	if strings.HasPrefix(tag.Key, "aws:") {
		return errors.GetAPIError(errors.ErrInvalidTagKey)
	}

	if !isValidTag(tag.Key) {
		return errors.GetAPIError(errors.ErrInvalidTagKey)
	}
	if !isValidTag(tag.Value) {
		return errors.GetAPIError(errors.ErrInvalidTagValue)
	}

	return nil
}

func isValidTag(str string) bool {
	for _, r := range str {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) &&
			!unicode.IsSpace(r) && !strings.ContainsRune(allowedTagChars, r) {
			return false
		}
	}
	return true
}
