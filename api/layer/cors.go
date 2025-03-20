package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/object"
)

const wildcard = "*"

var supportedMethods = map[string]struct{}{"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "DELETE": {}}

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

	prm := PrmObjectCreate{
		Container:    p.BktInfo.CID,
		Creator:      p.BktInfo.Owner,
		CreationTime: TimeNow(ctx),
		CopiesNumber: p.CopiesNumber,
		Attributes: map[string]string{
			s3headers.MetaType: s3headers.TypeBucketCORS,
		},
		Payload:     &buf,
		PayloadSize: uint64(buf.Len()),
	}

	if _, _, err := n.objectPutAndHash(ctx, prm, p.BktInfo); err != nil {
		return fmt.Errorf("create bucket CORS object: %w", err)
	}

	n.cache.PutCORS(n.Owner(ctx), p.BktInfo, cors)

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

	id, err := n.searchBucketMetaObjects(ctx, bktInfo.CID, s3headers.TypeBucketCORS)
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

	n.cache.PutCORS(owner, bktInfo, cors)

	return cors, nil
}

func (n *layer) DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error {
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
