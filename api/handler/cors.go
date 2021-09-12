package handler

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api"
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
		MaxAgeSeconds  int      `xml:"MaxAgeSeconds" json:"MaxAgeSeconds"`
	}
)

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
	if err != nil || info == nil {
		h.logAndSendError(w, "could not get cors", reqInfo, err)
		return
	}
	cors := &CORSConfiguration{}
	if err = json.Unmarshal(info, cors); err != nil {
		h.logAndSendError(w, "could not unmarshal json to cors", reqInfo, err)
	} else if err = api.EncodeToResponse(w, cors); err != nil {
		h.logAndSendError(w, "could not encode cors to response", reqInfo, err)
	}

	origin := reqInfo.URL.Query().Get("Origin")
	if origin == "" {
		origin = "*"
	}

	var (
		allowMethods  string
		exposeHeaders string
		allowHeaders  string
	)

Loop:
	for _, rule := range cors.CORSRules {
		for _, o := range rule.AllowedOrigins {
			if o == "*" || origin == o {
				allowMethods = strings.Join(rule.AllowedMethods, ", ")
				exposeHeaders = strings.Join(rule.ExposeHeaders, ", ")
				allowHeaders = strings.Join(rule.AllowedHeaders, ", ")
				if origin == o {
					break Loop
				}
			}
		}
	}

	w.Header().Set(api.AccessControlAllowOrigin, origin)
	w.Header().Set(api.AccessControlAllowMethods, allowMethods)
	w.Header().Set(api.AccessControlExposeHeaders, exposeHeaders)
	w.Header().Set(api.AccessControlAllowHeaders, allowHeaders)
	api.WriteSuccessResponseHeadersOnly(w)
}

func (h *handler) PutBucketCorsHandler(w http.ResponseWriter, r *http.Request) {
	reqInfo := api.GetReqInfo(r.Context())
	cors := &CORSConfiguration{}
	if err := xml.NewDecoder(r.Body).Decode(cors); err != nil {
		h.logAndSendError(w, "could not parse cors configuration", reqInfo, err)
		return
	}

	if cors.CORSRules == nil {
		h.logAndSendError(w, "could not parse cors rules", reqInfo, nil)
	}

	bktInfo, err := h.obj.GetBucketInfo(r.Context(), reqInfo.BucketName)
	if err != nil {
		h.logAndSendError(w, "could not get bucket info", reqInfo, err)
		return
	}

	if err = checkOwner(bktInfo, r.Header.Get(api.AmzExpectedBucketOwner)); err != nil {
		h.logAndSendError(w, "expected owner doesn't match", reqInfo, err)
		return
	}

	xml, err := xml.Marshal(cors)
	if err != nil {
		h.logAndSendError(w, "could not encode cors configuration to xml", reqInfo, err)
		return
	}

	p := &layer.PutCORSParams{
		BktInfo:               bktInfo,
		CORSConfigurationJSON: xml,
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

	if err := h.obj.DeleteBucketCORS(r.Context(), bktInfo); err != nil {
		h.logAndSendError(w, "could not delete cors", reqInfo, err)
	}

	api.WriteSuccessResponseHeadersOnly(w)
}
