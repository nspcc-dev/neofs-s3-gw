package handler

import (
	"encoding/xml"
	"net/http"
	"strings"
	"unicode"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

const (
	allowedTagChars = "+-=._:/@"

	keyTagMaxLength   = 128
	valueTagMaxLength = 256
)

func (h *handler) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	tagging := new(Tagging)
	if err := xml.NewDecoder(r.Body).Decode(tagging); err != nil {
		h.logAndSendError(w, "could not decode body", reqInfo, errors.GetAPIError(errors.ErrMalformedXML))
		return
	}

	if err := checkTagSet(tagging.TagSet); err != nil {
		h.logAndSendError(w, "some tags are invalid", reqInfo, err)
		return
	}

	p := &layer.HeadObjectParams{
		Bucket:    reqInfo.BucketName,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	tagSet := make(map[string]string, len(tagging.TagSet))
	for _, tag := range tagging.TagSet {
		tagSet[tag.Key] = tag.Value
	}

	p2 := &layer.PutTaggingParams{
		ObjectInfo: objInfo,
		TagSet:     tagSet,
	}

	if err = h.obj.PutObjectTagging(r.Context(), p2); err != nil {
		h.logAndSendError(w, "could not put object tagging", reqInfo, err)
		return
	}
}

func (h *handler) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	p := &layer.HeadObjectParams{
		Bucket:    reqInfo.BucketName,
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

	tagging := &Tagging{}
	for k, v := range tagSet {
		tagging.TagSet = append(tagging.TagSet, Tag{Key: k, Value: v})
	}

	w.Header().Set(api.AmzVersionID, objInfo.Version())
	if err = api.EncodeToResponse(w, tagging); err != nil {
		h.logAndSendError(w, "something went wrong", reqInfo, err)
	}
}

func checkTagSet(tagSet []Tag) error {
	if len(tagSet) > 10 {
		return errors.GetAPIError(errors.ErrInvalidTag)
	}

	for _, tag := range tagSet {
		if err := checkTag(tag); err != nil {
			return err
		}
	}

	return nil
}

func (h *handler) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	p := &layer.HeadObjectParams{
		Bucket:    reqInfo.BucketName,
		Object:    reqInfo.ObjectName,
		VersionID: reqInfo.URL.Query().Get("versionId"),
	}

	objInfo, err := h.obj.GetObjectInfo(r.Context(), p)
	if err != nil {
		h.logAndSendError(w, "could not get object info", reqInfo, err)
		return
	}

	if err = h.obj.DeleteObjectTagging(r.Context(), objInfo); err != nil {
		h.logAndSendError(w, "could not delete object tagging", reqInfo, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func checkTag(tag Tag) error {
	if len(tag.Key) < 1 || len(tag.Key) > keyTagMaxLength {
		return errors.GetAPIError(errors.ErrInvalidTag)
	}
	if len(tag.Value) < 1 || len(tag.Value) > valueTagMaxLength {
		return errors.GetAPIError(errors.ErrInvalidTag)
	}

	if strings.HasPrefix(tag.Key, "aws:") {
		return errors.GetAPIError(errors.ErrInvalidTag)
	}

	if err := checkCharacters(tag.Key); err != nil {
		return err
	}
	if err := checkCharacters(tag.Value); err != nil {
		return err
	}

	return nil
}

func checkCharacters(str string) error {
	for _, r := range str {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) &&
			!unicode.IsSpace(r) && !strings.ContainsRune(allowedTagChars, r) {
			return errors.GetAPIError(errors.ErrInvalidTag)
		}
	}
	return nil
}
