package layer

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"go.uber.org/zap"
)

type (
	// BucketACL extends BucketInfo by eacl.Table.
	BucketACL struct {
		Info *data.BucketInfo
		EACL *eacl.Table
	}
)

const locationConstraintAttr = ".s3-location-constraint"

func (n *layer) containerInfo(ctx context.Context, idCnr *cid.ID) (*data.BucketInfo, error) {
	var (
		err error
		res *container.Container
		rid = api.GetRequestID(ctx)

		info = &data.BucketInfo{
			CID:  idCnr,
			Name: idCnr.String(),
		}
	)
	res, err = n.neoFS.Container(ctx, *idCnr)
	if err != nil {
		n.log.Error("could not fetch container",
			zap.Stringer("cid", idCnr),
			zap.String("request_id", rid),
			zap.Error(err))

		if strings.Contains(err.Error(), "container not found") {
			return nil, errors.GetAPIError(errors.ErrNoSuchBucket)
		}
		return nil, err
	}

	info.Owner = res.OwnerID()
	info.BasicACL = res.BasicACL()

	for _, attr := range res.Attributes() {
		switch key, val := attr.Key(), attr.Value(); key {
		case container.AttributeName:
			info.Name = val
		case container.AttributeTimestamp:
			unix, err := strconv.ParseInt(attr.Value(), 10, 64)
			if err != nil {
				n.log.Error("could not parse container creation time",
					zap.Stringer("cid", idCnr),
					zap.String("request_id", rid),
					zap.String("created_at", val),
					zap.Error(err))

				continue
			}

			info.Created = time.Unix(unix, 0)
		case locationConstraintAttr:
			info.LocationConstraint = val
		}
	}

	if err := n.bucketCache.Put(info); err != nil {
		n.log.Warn("could not put bucket info into cache",
			zap.Stringer("cid", idCnr),
			zap.String("bucket_name", info.Name),
			zap.Error(err))
	}

	return info, nil
}

func (n *layer) containerList(ctx context.Context) ([]*data.BucketInfo, error) {
	var (
		err error
		own = n.Owner(ctx)
		res []cid.ID
		rid = api.GetRequestID(ctx)
	)
	res, err = n.neoFS.UserContainers(ctx, *own)
	if err != nil {
		n.log.Error("could not list user containers",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]*data.BucketInfo, 0, len(res))
	for i := range res {
		info, err := n.containerInfo(ctx, &res[i])
		if err != nil {
			n.log.Error("could not fetch container info",
				zap.String("request_id", rid),
				zap.Error(err))
			continue
		}

		list = append(list, info)
	}

	return list, nil
}

func (n *layer) createContainer(ctx context.Context, p *CreateBucketParams) (*cid.ID, error) {
	var err error
	bktInfo := &data.BucketInfo{
		Name:               p.Name,
		Owner:              n.Owner(ctx),
		Created:            time.Now(),
		BasicACL:           p.ACL,
		LocationConstraint: p.LocationConstraint,
	}

	var locConstAttr *container.Attribute

	if p.LocationConstraint != "" {
		locConstAttr = container.NewAttribute()
		locConstAttr.SetKey(locationConstraintAttr)
		locConstAttr.SetValue(p.LocationConstraint)
	}

	if bktInfo.CID, err = n.neoFS.CreateContainer(ctx, PrmContainerCreate{
		Creator:                     *bktInfo.Owner,
		Policy:                      *p.Policy,
		Name:                        p.Name,
		SessionToken:                p.SessionToken,
		Time:                        bktInfo.Created,
		BasicACL:                    acl.BasicACL(p.ACL),
		LocationConstraintAttribute: locConstAttr,
	}); err != nil {
		return nil, err
	}

	if err = n.setContainerEACLTable(ctx, bktInfo.CID, p.EACL); err != nil {
		return nil, err
	}

	if err = n.bucketCache.Put(bktInfo); err != nil {
		n.log.Warn("couldn't put bucket info into cache",
			zap.String("bucket name", bktInfo.Name),
			zap.Stringer("bucket cid", bktInfo.CID),
			zap.Error(err))
	}

	return bktInfo.CID, nil
}

func (n *layer) setContainerEACLTable(ctx context.Context, cid *cid.ID, table *eacl.Table) error {
	table.SetCID(cid)

	boxData, err := GetBoxData(ctx)
	if err == nil {
		table.SetSessionToken(boxData.Gate.SessionTokenForSetEACL())
	}

	if err := n.neoFS.SetContainerEACL(ctx, *table); err != nil {
		return err
	}

	return n.waitEACLPresence(ctx, *cid, table, defaultWaitParams())
}

func (n *layer) GetContainerEACL(ctx context.Context, cid *cid.ID) (*eacl.Table, error) {
	return n.neoFS.ContainerEACL(ctx, *cid)
}

type waitParams struct {
	WaitTimeout  time.Duration
	PollInterval time.Duration
}

func defaultWaitParams() *waitParams {
	return &waitParams{
		WaitTimeout:  60 * time.Second,
		PollInterval: 3 * time.Second,
	}
}

func (n *layer) waitEACLPresence(ctx context.Context, cid cid.ID, table *eacl.Table, params *waitParams) error {
	exp, err := table.Marshal()
	if err != nil {
		return fmt.Errorf("couldn't marshal eacl: %w", err)
	}

	wctx, cancel := context.WithTimeout(ctx, params.WaitTimeout)
	defer cancel()
	ticker := time.NewTimer(params.PollInterval)
	defer ticker.Stop()
	wdone := wctx.Done()
	done := ctx.Done()
	var eaclTable *eacl.Table
	var got []byte
	for {
		select {
		case <-done:
			return ctx.Err()
		case <-wdone:
			return wctx.Err()
		case <-ticker.C:
			eaclTable, err = n.neoFS.ContainerEACL(ctx, cid)
			if err == nil {
				got, err = eaclTable.Marshal()
				if err != nil {
					// not expected, but if occurred - doesn't make sense to continue
					return fmt.Errorf("marshal received eACL: %w", err)
				} else if bytes.Equal(exp, got) {
					return nil
				}
			}
			ticker.Reset(params.PollInterval)
		}
	}
}

func (n *layer) deleteContainer(ctx context.Context, idCnr *cid.ID) error {
	var sessionToken *session.Token
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionToken = boxData.Gate.SessionTokenForDelete()
	}
	return n.neoFS.DeleteContainer(ctx, *idCnr, sessionToken)
}
