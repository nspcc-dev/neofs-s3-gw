package handler

import (
	"encoding/xml"
	"fmt"
)

// ListBucketsResponse -- format for list buckets response.
type ListBucketsResponse struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult" json:"-"`

	Owner Owner

	// Container for one or more buckets.
	Buckets struct {
		Buckets []Bucket `xml:"Bucket"`
	} // Buckets are nested
}

// ListObjectsV1Response -- format for ListObjectsV1 response.
type ListObjectsV1Response struct {
	XMLName        xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult" json:"-"`
	CommonPrefixes []CommonPrefix `xml:"CommonPrefixes"`
	Contents       []Object       `xml:"Contents"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	EncodingType   string         `xml:"EncodingType,omitempty"`
	IsTruncated    bool           `xml:"IsTruncated"`
	Marker         string         `xml:"Marker"`
	MaxKeys        int            `xml:"MaxKeys"`
	Name           string         `xml:"Name"`
	NextMarker     string         `xml:"NextMarker,omitempty"`
	Prefix         string         `xml:"Prefix"`
}

// ListObjectsV2Response -- format for ListObjectsV2 response.
type ListObjectsV2Response struct {
	XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult" json:"-"`
	CommonPrefixes        []CommonPrefix `xml:"CommonPrefixes"`
	Contents              []Object       `xml:"Contents"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
	IsTruncated           bool           `xml:"IsTruncated"`
	KeyCount              int            `xml:"KeyCount"`
	MaxKeys               int            `xml:"MaxKeys"`
	Name                  string         `xml:"Name"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	Prefix                string         `xml:"Prefix"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
}

// Bucket container for bucket metadata.
type Bucket struct {
	Name         string
	CreationDate string // time string of format "2006-01-02T15:04:05.000Z"
}

// AccessControlPolicy contains ACL.
type AccessControlPolicy struct {
	XMLName           xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy" json:"-"`
	Owner             Owner
	AccessControlList []*Grant `xml:"AccessControlList>Grant"`
}

// Grant is container for Grantee data.
type Grant struct {
	Grantee    *Grantee
	Permission amazonS3Permission
}

// NewGrantee initializes new Grantee with specified granteeType.
func NewGrantee(t granteeType) *Grantee {
	return &Grantee{
		Type: t,
	}
}

// Grantee represents container (not NeoFS) for the person being granted
// permissions specified in https://docs.aws.amazon.com/AmazonS3/latest/API/API_Grantee.html.
type Grantee struct {
	// Screen name of the grantee.
	// Optional.
	DisplayName string
	// Email address of the grantee.
	// Optional.
	EmailAddress string
	// The canonical user ID of the grantee.
	// Optional.
	ID string
	// Type of grantee.
	// Required.
	Type granteeType
	// URI of the grantee group.
	// Optional.
	URI string
}

// layout of <Grantee> tag for XML encoding of Grantee, see Grantee.MarshalXML,
// Grantee.UnmarshalXML.
type granteeXMLBody struct {
	DisplayName  *string `xml:"DisplayName,omitempty"`
	EmailAddress *string `xml:"EmailAddress,omitempty"`
	ID           *string `xml:"ID,omitempty"`
	URI          *string `xml:"URI,omitempty"`
}

// MarshalXML provides xml.Marshaler for Grantee.
//
// XML scheme of Grantee is described in Amazon S3 docs
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html.
//
// MarshalXML overrides default encoding of Grantee layout because currently
// xml.Marshal doesn't provide convenient approach to work with prefixes in XML
// namespaces. According to docs, Grantee.Type is an attribute from the
// namespace with 'xsi' prefix.
//
// Here we use workaround proposed in corresponding Go issue
// https://github.com/golang/go/issues/9519#issuecomment-252196382.
func (x Grantee) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	var body granteeXMLBody
	if x.DisplayName != "" {
		body.DisplayName = &x.DisplayName
	}
	if x.EmailAddress != "" {
		body.EmailAddress = &x.EmailAddress
	}
	if x.ID != "" {
		body.ID = &x.ID
	}
	if x.URI != "" {
		body.URI = &x.URI
	}

	return e.Encode(struct {
		XMLName xml.Name `xml:"Grantee"`
		granteeXMLBody
		XMLNS string      `xml:"xmlns:xsi,attr"`
		Type  granteeType `xml:"xsi:type,attr"`
	}{
		granteeXMLBody: body,
		XMLNS:          "http://www.w3.org/2001/XMLSchema-instance",
		Type:           x.Type,
	})
}

// UnmarshalXML MarshalXML provides xml.Unmarshaler for Grantee.
//
// See MarshalXML for details.
func (x *Grantee) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	err := d.DecodeElement(&struct {
		granteeXMLBody
		Type *granteeType `xml:"type,attr"`
	}{
		granteeXMLBody: granteeXMLBody{
			DisplayName:  &x.DisplayName,
			EmailAddress: &x.EmailAddress,
			ID:           &x.ID,
			URI:          &x.URI,
		},
		Type: &x.Type,
	}, &start)
	if err != nil {
		return err
	}

	switch x.Type {
	default:
		return fmt.Errorf("invalid grantee type '%s'", x.Type)
	case granteeCanonicalUser, granteeGroup, granteeAmazonCustomerByEmail:
	}

	return nil
}

// Owner -- bucket owner/principal.
type Owner struct {
	ID          string
	DisplayName string
}

// CommonPrefix container for prefix response in ListObjects's response.
type CommonPrefix struct {
	Prefix string
}

// Object container for object metadata.
type Object struct {
	Key          string
	LastModified string // time string of format "2006-01-02T15:04:05.000Z"
	ETag         string `xml:"ETag,omitempty"`
	Size         int64

	// Owner of the object.
	Owner *Owner `xml:"Owner,omitempty"`

	// Class of storage used to store the object.
	StorageClass string `xml:"StorageClass,omitempty"`
}

// ObjectVersionResponse container for object version in the response of ListBucketObjectVersionsHandler.
type ObjectVersionResponse struct {
	ETag         string `xml:"ETag"`
	IsLatest     bool   `xml:"IsLatest"`
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Owner        Owner  `xml:"Owner"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass,omitempty"` // is empty!!
	VersionID    string `xml:"VersionId"`
}

// DeleteMarkerEntry container for deleted object's version in the response of ListBucketObjectVersionsHandler.
type DeleteMarkerEntry struct {
	IsLatest     bool   `xml:"IsLatest"`
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Owner        Owner  `xml:"Owner"`
	VersionID    string `xml:"VersionId"`
}

// StringMap is a map[string]string.
type StringMap map[string]string

// LocationResponse -- format for location response.
type LocationResponse struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint" json:"-"`
	Location string   `xml:",chardata"`
}

// CopyObjectResponse container returns ETag and LastModified of the successfully copied object.
type CopyObjectResponse struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult" json:"-"`
	LastModified string   // time string of format "2006-01-02T15:04:05.000Z"
	ETag         string   // md5sum of the copied object.
}

// ListObjectsVersionsResponse is a response of ListBucketObjectVersionsHandler.
type ListObjectsVersionsResponse struct {
	XMLName             xml.Name                `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult" json:"-"`
	EncodingType        string                  `xml:"EncodingType,omitempty"`
	Name                string                  `xml:"Name"`
	IsTruncated         bool                    `xml:"IsTruncated"`
	KeyMarker           string                  `xml:"KeyMarker"`
	NextKeyMarker       string                  `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string                  `xml:"NextVersionIdMarker,omitempty"`
	VersionIDMarker     string                  `xml:"VersionIdMarker"`
	DeleteMarker        []DeleteMarkerEntry     `xml:"DeleteMarker"`
	Version             []ObjectVersionResponse `xml:"Version"`
	CommonPrefixes      []CommonPrefix          `xml:"CommonPrefixes"`
}

// VersioningConfiguration contains VersioningConfiguration XML representation.
type VersioningConfiguration struct {
	XMLName   xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
	Status    string   `xml:"Status,omitempty"`
	MfaDelete string   `xml:"MfaDelete,omitempty"`
}

// Tagging contains tag set.
type Tagging struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Tagging"`
	TagSet  []Tag    `xml:"TagSet>Tag"`
}

// PostResponse contains result of posting object.
type PostResponse struct {
	Bucket string `xml:"Bucket"`
	Key    string `xml:"Key"`
	ETag   string `xml:"Etag"`
}

// Tag is an AWS key-value tag.
type Tag struct {
	Key   string
	Value string
}

// MarshalXML -- StringMap marshals into XML.
func (s StringMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	tokens := []xml.Token{start}

	for key, value := range s {
		t := xml.StartElement{}
		t.Name = xml.Name{
			Space: "",
			Local: key,
		}
		tokens = append(tokens, t, xml.CharData(value), xml.EndElement{Name: t.Name})
	}

	tokens = append(tokens, xml.EndElement{
		Name: start.Name,
	})

	for _, t := range tokens {
		if err := e.EncodeToken(t); err != nil {
			return fmt.Errorf("encode token: %w", err)
		}
	}

	// flush to ensure tokens are written
	return e.Flush()
}
