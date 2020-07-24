package handler

import (
	"context"
	"encoding/xml"
	"net/http"
	"time"

	"github.com/minio/minio/auth"
	"github.com/minio/minio/neofs/api"
	"github.com/nspcc-dev/neofs-api-go/container"
	"github.com/nspcc-dev/neofs-api-go/refs"
	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type (
	// Owner - bucket owner/principal
	Owner struct {
		ID          string
		DisplayName string
	}

	// Bucket container for bucket metadata
	Bucket struct {
		Name         string
		CreationDate string // time string of format "2006-01-02T15:04:05.000Z"
	}

	// ListBucketsResponse - format for list buckets response
	ListBucketsResponse struct {
		XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult" json:"-"`

		Owner Owner

		// Container for one or more buckets.
		Buckets struct {
			Buckets []*Bucket `xml:"Bucket"`
		} // Buckets are nested
	}

	cnrInfoParams struct {
		cid refs.CID
		con *grpc.ClientConn
		tkn *service.BearerTokenMsg
	}
)

func (h *handler) getContainerInfo(ctx context.Context, p cnrInfoParams) (*Bucket, error) {
	var (
		err error
		res *container.GetResponse
	)

	req := new(container.GetRequest)
	req.SetCID(p.cid)
	req.SetTTL(service.SingleForwardingTTL)
	req.SetBearer(p.tkn)

	if err = service.SignRequestData(h.key, req); err != nil {
		return nil, errors.Wrap(err, "could not sign container info request")
	} else if res, err = container.NewServiceClient(p.con).Get(ctx, req); err != nil {
		return nil, errors.Wrap(err, "could not fetch container info")
	}

	// TODO should extract nice name
	//  	and datetime from container info:
	_ = res

	return &Bucket{
		Name:         p.cid.String(),
		CreationDate: new(time.Time).Format(time.RFC3339),
	}, nil
}

func (h *handler) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		uid = h.uid
		inf *Bucket
		con *grpc.ClientConn
		res *container.ListResponse
		tkn *service.BearerTokenMsg
	)

	// TODO think about deadlines
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if tkn, err = auth.GetBearerToken(ctx); err != nil {
		h.log.Error("could not fetch bearer token",
			zap.Error(err))

		e := api.GetAPIError(api.ErrInternalError)

		api.WriteErrorResponse(ctx, w, api.Error{
			Code:           e.Code,
			Description:    err.Error(),
			HTTPStatusCode: e.HTTPStatusCode,
		}, r.URL)

		return
	}

	req := new(container.ListRequest)
	req.OwnerID = uid
	req.SetTTL(service.SingleForwardingTTL)
	req.SetBearer(tkn)
	// req.SetVersion(APIVersion) ??

	if con, err = h.cli.GetConnection(ctx); err != nil {
		h.log.Error("could not get connection",
			zap.Error(err))

		e := api.GetAPIError(api.ErrInternalError)

		api.WriteErrorResponse(ctx, w, api.Error{
			Code:           e.Code,
			Description:    err.Error(),
			HTTPStatusCode: e.HTTPStatusCode,
		}, r.URL)

		return
	} else if err = service.SignRequestData(h.key, req); err != nil {
		h.log.Error("could not prepare request",
			zap.Error(err))

		e := api.GetAPIError(api.ErrInternalError)

		api.WriteErrorResponse(ctx, w, api.Error{
			Code:           e.Code,
			Description:    err.Error(),
			HTTPStatusCode: e.HTTPStatusCode,
		}, r.URL)

		return
	} else if res, err = container.NewServiceClient(con).List(ctx, req); err != nil {
		h.log.Error("could not list buckets",
			zap.Error(err))

		e := api.GetAPIError(api.ErrInternalError)

		api.WriteErrorResponse(ctx, w, api.Error{
			Code:           e.Code,
			Description:    err.Error(),
			HTTPStatusCode: e.HTTPStatusCode,
		}, r.URL)

		return
	}

	result := &ListBucketsResponse{Owner: Owner{
		ID:          uid.String(),
		DisplayName: uid.String(),
	}}

	params := cnrInfoParams{con: con, tkn: tkn}

	for _, cid := range res.CID {
		// should receive each container info (??):
		params.cid = cid

		if inf, err = h.getContainerInfo(ctx, params); err != nil {
			h.log.Error("could not fetch bucket info",
				zap.Error(err))

			e := api.GetAPIError(api.ErrInternalError)

			api.WriteErrorResponse(ctx, w, api.Error{
				Code:           e.Code,
				Description:    err.Error(),
				HTTPStatusCode: e.HTTPStatusCode,
			}, r.URL)

			return
		}

		result.Buckets.Buckets = append(result.Buckets.Buckets, inf)
	}

	// Generate response.
	encodedSuccessResponse := api.EncodeResponse(result)

	// Write response.
	api.WriteSuccessResponseXML(w, encodedSuccessResponse)
}
