package layer

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"slices"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
)

const (
	wildcard = "*"

	attributeCors          = "CORS"
	attributeTags          = "S3_TAGS"
	attributeSettings      = "S3_SETTINGS"
	attributeNotifications = "S3_NOTIFICATIONS"
)

var supportedMethods = map[string]struct{}{"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "DELETE": {}}

func (n *layer) storeAttribute(ctx context.Context, cID cid.ID, attributeName string, payload any, sessionTokenV2 *session.Token) error {
	pl, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err = n.neoFS.SetContainerAttribute(ctx, cID, attributeName, string(pl), sessionTokenV2); err != nil {
		return fmt.Errorf("could't store %s %s: %w", cID.EncodeToString(), attributeName, err)
	}

	return nil
}

func (n *layer) PutBucketCORS(ctx context.Context, p *PutCORSParams) error {
	var (
		buf  bytes.Buffer
		tee  = io.TeeReader(p.Reader, &buf)
		cors = &data.CORSConfiguration{}
	)

	if err := xml.NewDecoder(tee).Decode(cors); err != nil {
		return fmt.Errorf("xml decode cors: %w", err)
	}

	if cors.CORSRules == nil {
		return s3errors.GetAPIError(s3errors.ErrMalformedXML)
	}

	if err := checkCORS(cors); err != nil {
		return err
	}

	var sessionTokenV2 *session.Token
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionTokenV2 = boxData.Gate.SessionTokenV2
	}

	if err = n.storeAttribute(ctx, p.BktInfo.CID, attributeCors, cors.CORSRules, sessionTokenV2); err != nil {
		return fmt.Errorf("store bucket CORS: %w", err)
	}

	n.cache.DeleteBucket(p.BktInfo.Name)

	return nil
}

func (n *layer) GetBucketCORS(_ context.Context, bktInfo *data.BucketInfo) (*data.CORSConfiguration, error) {
	item, err := n.bucketSettingsItem(bktInfo)
	if err != nil {
		return nil, err
	}

	if item.CORS == nil {
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchCORSConfiguration)
	}

	return item.CORS, nil
}

func (n *layer) DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error {
	var sessionTokenV2 *session.Token
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionTokenV2 = boxData.Gate.SessionTokenV2
	}

	if err = n.neoFS.RemoveContainerAttribute(ctx, bktInfo.CID, attributeCors, sessionTokenV2); err != nil {
		return fmt.Errorf("remove bucket CORS: %w", err)
	}

	n.cache.DeleteBucket(bktInfo.Name)

	return nil
}

func checkCORS(cors *data.CORSConfiguration) error {
	for _, r := range cors.CORSRules {
		for _, m := range r.AllowedMethods {
			if _, ok := supportedMethods[m]; !ok {
				return s3errors.GetAPIErrorWithError(s3errors.ErrCORSUnsupportedMethod, fmt.Errorf("unsupported method is %s", m))
			}
		}
		if slices.Contains(r.ExposeHeaders, wildcard) {
			return s3errors.GetAPIError(s3errors.ErrCORSWildcardExposeHeaders)
		}
	}
	return nil
}
