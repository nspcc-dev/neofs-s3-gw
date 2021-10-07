package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
)

type (
	// CORSConfiguration stores CORS configuration of a request.
	CORSConfiguration struct {
		XMLName   xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CORSConfiguration" json:"-"`
		CORSRules []CORSRule `xml:"CORSRule" json:"CORSRules"`
	}
	// CORSRule stores rules for CORS in a bucket.
	CORSRule struct {
		ID             string   `xml:"ID,omitempty" json:"ID,omitempty"`
		AllowedHeaders []string `xml:"AllowedHeader" json:"AllowedHeaders"`
		AllowedMethods []string `xml:"AllowedMethod" json:"AllowedMethods"`
		AllowedOrigins []string `xml:"AllowedOrigin" json:"AllowedOrigins"`
		ExposeHeaders  []string `xml:"ExposeHeader" json:"ExposeHeaders"`
		MaxAgeSeconds  int      `xml:"MaxAgeSeconds,omitempty" json:"MaxAgeSeconds,omitempty"`
	}
)

const (
	// DefaultMaxAge -- default value of Access-Control-Max-Age if this value is not set in a rule.
	DefaultMaxAge = 600
	wildcard      = "*"
)

var supportedMethods = map[string]struct{}{"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "DELETE": {}}

func (h *handler) GetBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	info, err := h.obj.GetBucketCORS(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get cors", reqInfo, err)
		return
	}

	api.WriteResponse(w, http.StatusOK, info, api.MimeNone)
}

func (h *handler) PutBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	cors := &CORSConfiguration{}
	if err := xml.NewDecoder(r.Body).Decode(cors); err != nil {
		h.logAndSendError(w, "could not parse cors configuration", reqInfo, err)
		return
	}
	if cors.CORSRules == nil {
		h.logAndSendError(w, "could not parse cors rules", reqInfo, errors.GetAPIError(errors.ErrMalformedXML))
		return
	}

	if err = checkCORS(cors); err != nil {
		h.logAndSendError(w, "invalid cors configuration", reqInfo, err)
		return
	}

	xml, err := xml.Marshal(cors)
	if err != nil {
		h.logAndSendError(w, "could not encode cors configuration to xml", reqInfo, err)
		return
	}

	p := &layer.PutCORSParams{
		BktInfo:           bktInfo,
		CORSConfiguration: xml,
	}

	if err = h.obj.PutBucketCORS(r.Context(), p); err != nil {
		h.logAndSendError(w, "could not put cors configuration", reqInfo, err)
		return
	}

	api.WriteSuccessResponseHeadersOnly(w)
}

func (h *handler) DeleteBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	if err := h.obj.DeleteBucketCORS(r.Context(), bktInfo); err != nil {
		h.logAndSendError(w, "could not delete cors", reqInfo, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) AppendCORSHeaders(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		return
	}
	origin := r.Header.Get(api.Origin)
	if origin == "" {
		return
	}
	reqInfo := api.GetReqInfo(r.Context())
	if reqInfo.BucketName == "" {
		return
	}
	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		return
	}

	info, err := h.obj.GetBucketCORS(r.Context(), bktInfo)
	if err != nil {
		return
	}
	cors := &CORSConfiguration{}
	if err = xml.Unmarshal(info, cors); err != nil {
		return
	}
	withCredentials := r.Header.Get(api.Authorization) != ""

	for _, rule := range cors.CORSRules {
		for _, o := range rule.AllowedOrigins {
			if o == origin {
				for _, m := range rule.AllowedMethods {
					if m == r.Method {
						w.Header().Set(api.AccessControlAllowOrigin, origin)
						w.Header().Set(api.AccessControlAllowMethods, strings.Join(rule.AllowedMethods, ", "))
						w.Header().Set(api.AccessControlAllowCredentials, "true")
						w.Header().Set(api.Vary, api.Origin)
						return
					}
				}
			}
			if o == wildcard {
				for _, m := range rule.AllowedMethods {
					if m == r.Method {
						if withCredentials {
							w.Header().Set(api.AccessControlAllowOrigin, origin)
							w.Header().Set(api.AccessControlAllowCredentials, "true")
							w.Header().Set(api.Vary, api.Origin)
						} else {
							w.Header().Set(api.AccessControlAllowOrigin, o)
						}
						w.Header().Set(api.AccessControlAllowMethods, strings.Join(rule.AllowedMethods, ", "))
						return
					}
				}
			}
		}
	}
}

func (h *handler) Preflight(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	origin := r.Header.Get(api.Origin)
	if origin == "" {
		h.logAndSendError(w, "origin request header needed", reqInfo, errors.GetAPIError(errors.ErrBadRequest))
	}

	method := r.Header.Get(api.AccessControlRequestMethod)
	if method == "" {
		h.logAndSendError(w, "Access-Control-Request-Method request header needed", reqInfo, errors.GetAPIError(errors.ErrBadRequest))
		return
	}

	var headers []string
	requestHeaders := r.Header.Get(api.AccessControlRequestHeaders)
	if requestHeaders != "" {
		headers = strings.Split(requestHeaders, ", ")
	}

	info, err := h.obj.GetBucketCORS(r.Context(), bktInfo)
	if err != nil {
		h.logAndSendError(w, "could not get cors", reqInfo, err)
		return
	}
	cors := &CORSConfiguration{}
	if err = xml.Unmarshal(info, cors); err != nil {
		h.logAndSendError(w, "could not parse cors configuration", reqInfo, err)
		return
	}

	for _, rule := range cors.CORSRules {
		for _, o := range rule.AllowedOrigins {
			if o == origin || o == wildcard {
				for _, m := range rule.AllowedMethods {
					if m == method {
						if !checkSubslice(rule.AllowedHeaders, headers) {
							continue
						}
						w.Header().Set(api.AccessControlAllowOrigin, o)
						w.Header().Set(api.AccessControlAllowMethods, strings.Join(rule.AllowedMethods, ", "))
						if headers != nil {
							w.Header().Set(api.AccessControlAllowHeaders, requestHeaders)
						}
						if rule.ExposeHeaders != nil {
							w.Header().Set(api.AccessControlExposeHeaders, strings.Join(rule.ExposeHeaders, ", "))
						}
						if rule.MaxAgeSeconds > 0 || rule.MaxAgeSeconds == -1 {
							w.Header().Set(api.AccessControlMaxAge, strconv.Itoa(rule.MaxAgeSeconds))
						} else {
							w.Header().Set(api.AccessControlMaxAge, strconv.Itoa(h.cfg.DefaultMaxAge))
						}
						if o != wildcard {
							w.Header().Set(api.AccessControlAllowCredentials, "true")
						}
						api.WriteSuccessResponseHeadersOnly(w)
						return
					}
				}
			}
		}
	}
	h.logAndSendError(w, "Forbidden", reqInfo, errors.GetAPIError(errors.ErrAccessDenied))
}

func checkCORS(cors *CORSConfiguration) error {
	for _, r := range cors.CORSRules {
		for _, m := range r.AllowedMethods {
			if _, ok := supportedMethods[m]; !ok {
				return fmt.Errorf("unsupported HTTP method in CORS config %s", m)
			}
		}
		for _, h := range r.ExposeHeaders {
			if h == wildcard {
				return fmt.Errorf("ExposeHeader \"*\" contains wildcard. We currently do not support wildcard " +
					"for ExposeHeader")
			}
		}
	}
	return nil
}

func checkSubslice(slice []string, subSlice []string) bool {
	if sliceContains(slice, wildcard) {
		return true
	}
	if len(subSlice) > len(slice) {
		return false
	}
	for _, r := range subSlice {
		if !sliceContains(slice, r) {
			return false
		}
	}
	return true
}

func sliceContains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
