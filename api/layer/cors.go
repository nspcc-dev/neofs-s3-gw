package layer

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

const (
	wildcard = "*"

	attributeCors = "CORS"
	attributeTags = "S3_TAGS"
)

var supportedMethods = map[string]struct{}{"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "DELETE": {}}

func (n *layer) storeAttribute(ctx context.Context, cID cid.ID, attributeName string, payload any, sessionToken *session.Container) error {
	pl, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err = n.neoFS.SetContainerAttribute(ctx, cID, attributeName, string(pl), sessionToken); err != nil {
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

	var sessionToken *session.Container
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionToken = boxData.Gate.SessionTokenForSetAttribute()
	}

	if err = n.storeAttribute(ctx, p.BktInfo.CID, attributeCors, cors.CORSRules, sessionToken); err != nil {
		return fmt.Errorf("store bucket CORS: %w", err)
	}

	n.cache.PutCORS(n.Owner(ctx), p.BktInfo, cors)
	n.cache.DeleteBucket(p.BktInfo.Name)

	return nil
}

func (n *layer) GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (*data.CORSConfiguration, error) {
	var (
		err   error
		owner = n.Owner(ctx)
	)

	if cors := n.cache.GetCORS(owner, bktInfo); cors != nil {
		return cors, nil
	}

	var corsRules []data.CORSRule
	if bktInfo.AttributeCors != "" {
		if err = json.Unmarshal([]byte(bktInfo.AttributeCors), &corsRules); err != nil {
			return nil, fmt.Errorf("malformed data: %w", err)
		}

		cors := &data.CORSConfiguration{
			CORSRules: corsRules,
		}

		n.cache.PutCORS(owner, bktInfo, cors)
		return cors, nil
	}

	id, err := n.searchBucketMetaObjects(ctx, bktInfo, s3headers.TypeBucketCORS)
	if err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	if id.IsZero() {
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchCORSConfiguration)
	}

	obj, err := n.objectGet(ctx, bktInfo, id)
	if err != nil {
		return nil, err
	}

	cors := &data.CORSConfiguration{}

	if err = xml.Unmarshal(obj.Payload(), &cors); err != nil {
		return nil, fmt.Errorf("unmarshal cors: %w", err)
	}

	boxData, err := GetBoxData(ctx)
	if err == nil {
		// Migrate CORS to contract.
		if err = n.storeAttribute(ctx, bktInfo.CID, attributeCors, cors.CORSRules, boxData.Gate.SessionTokenForSetAttribute()); err != nil {
			return nil, fmt.Errorf("migrate bucket CORS: %w", err)
		}
		if err = n.deleteBucketCORS(ctx, bktInfo); err != nil {
			return nil, fmt.Errorf("delete bucket CORS: %w", err)
		}
	}

	n.cache.PutCORS(owner, bktInfo, cors)
	n.cache.DeleteBucket(bktInfo.Name)

	return cors, nil
}

func (n *layer) DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error {
	if err := n.deleteBucketCORS(ctx, bktInfo); err != nil {
		return fmt.Errorf("delete bucket CORS: %w", err)
	}

	var sessionToken *session.Container
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionToken = boxData.Gate.SessionTokenForRemoveAttribute()
	}

	if err = n.neoFS.RemoveContainerAttribute(ctx, bktInfo.CID, attributeCors, sessionToken); err != nil {
		return fmt.Errorf("remove bucket CORS: %w", err)
	}

	n.cache.DeleteCORS(bktInfo)
	n.cache.DeleteBucket(bktInfo.Name)

	return nil
}

func (n *layer) deleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error {
	fs := make(object.SearchFilters, 0, 2)
	fs.AddFilter(s3headers.MetaType, s3headers.TypeBucketCORS, object.MatchStringEqual)
	fs.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)

	var opts client.SearchObjectsOptions
	if bt := bearerTokenFromContext(ctx, bktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, fs, nil, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return fmt.Errorf("search object version: %w", err)
	}

	if len(res) == 0 {
		return nil
	}

	for i := range res {
		if err = n.objectDelete(ctx, bktInfo, res[i].ID); err != nil {
			return fmt.Errorf("couldn't delete bucket CORS object: %w", err)
		}
	}

	n.cache.DeleteCORS(bktInfo)

	return nil
}

func checkCORS(cors *data.CORSConfiguration) error {
	for _, r := range cors.CORSRules {
		for _, m := range r.AllowedMethods {
			if _, ok := supportedMethods[m]; !ok {
				return s3errors.GetAPIErrorWithError(s3errors.ErrCORSUnsupportedMethod, fmt.Errorf("unsupported method is %s", m))
			}
		}
		for _, h := range r.ExposeHeaders {
			if h == wildcard {
				return s3errors.GetAPIError(s3errors.ErrCORSWildcardExposeHeaders)
			}
		}
	}
	return nil
}
