package layer

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"go.uber.org/zap"
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
		return err
	}

	if cors.CORSRules == nil {
		return errors.GetAPIError(errors.ErrMalformedXML)
	}

	if err := checkCORS(cors); err != nil {
		return err
	}

	s := &PutSystemObjectParams{
		BktInfo:  p.BktInfo,
		ObjName:  p.BktInfo.CORSObjectName(),
		Metadata: map[string]string{},
		Prefix:   "",
		Reader:   &buf,
		Size:     int64(buf.Len()),
	}

	_, err := n.putSystemObjectIntoNeoFS(ctx, s)
	if err != nil {
		return err
	}

	if err = n.systemCache.PutCORS(systemObjectKey(p.BktInfo, s.ObjName), cors); err != nil {
		n.log.Error("couldn't cache system object", zap.Error(err))
	}

	return nil
}

func (n *layer) GetBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) (*data.CORSConfiguration, error) {
	cors, err := n.getCORS(ctx, bktInfo, bktInfo.CORSObjectName())
	if err != nil {
		if errors.IsS3Error(err, errors.ErrNoSuchKey) {
			return nil, errors.GetAPIError(errors.ErrNoSuchCORSConfiguration)
		}
		return nil, err
	}

	return cors, nil
}

func (n *layer) DeleteBucketCORS(ctx context.Context, bktInfo *data.BucketInfo) error {
	return n.DeleteSystemObject(ctx, bktInfo, bktInfo.CORSObjectName())
}

func checkCORS(cors *data.CORSConfiguration) error {
	for _, r := range cors.CORSRules {
		for _, m := range r.AllowedMethods {
			if _, ok := supportedMethods[m]; !ok {
				return errors.GetAPIErrorWithError(errors.ErrCORSUnsupportedMethod, fmt.Errorf("unsupported method is %s", m))
			}
		}
		for _, h := range r.ExposeHeaders {
			if h == wildcard {
				return errors.GetAPIError(errors.ErrCORSWildcardExposeHeaders)
			}
		}
	}
	return nil
}
