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
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"go.uber.org/zap"
)

type (
	// BucketACL extends BucketInfo by eacl.Table.
	BucketACL struct {
		Info *data.BucketInfo
		EACL *eacl.Table
	}
)

func (n *layer) containerInfo(ctx context.Context, cid *cid.ID) (*data.BucketInfo, error) {
	var (
		err error
		res *container.Container
		rid = api.GetRequestID(ctx)

		info = &data.BucketInfo{
			CID:  cid,
			Name: cid.String(),
		}
	)
	res, err = n.pool.GetContainer(ctx, cid, n.CallOptions(ctx)...)
	if err != nil {
		n.log.Error("could not fetch container",
			zap.Stringer("cid", cid),
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
					zap.Stringer("cid", cid),
					zap.String("request_id", rid),
					zap.String("created_at", val),
					zap.Error(err))

				continue
			}

			info.Created = time.Unix(unix, 0)
		}
	}

	if err := n.bucketCache.Put(info); err != nil {
		n.log.Warn("could not put bucket info into cache",
			zap.Stringer("cid", cid),
			zap.String("bucket_name", info.Name),
			zap.Error(err))
	}

	return info, nil
}

func (n *layer) containerList(ctx context.Context) ([]*data.BucketInfo, error) {
	var (
		err error
		own = n.Owner(ctx)
		res []*cid.ID
		rid = api.GetRequestID(ctx)
	)
	res, err = n.pool.ListContainers(ctx, own, n.CallOptions(ctx)...)
	if err != nil {
		n.log.Error("could not fetch container",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]*data.BucketInfo, 0, len(res))
	for _, cid := range res {
		info, err := n.containerInfo(ctx, cid)
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
		Name:     p.Name,
		Owner:    n.Owner(ctx),
		Created:  time.Now(),
		BasicACL: p.ACL,
	}
	cnr := container.New(
		container.WithPolicy(p.Policy),
		container.WithCustomBasicACL(p.ACL),
		container.WithAttribute(container.AttributeName, p.Name),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(bktInfo.Created.Unix(), 10)))

	cnr.SetSessionToken(p.SessionToken)
	cnr.SetOwnerID(bktInfo.Owner)

	if bktInfo.CID, err = n.pool.PutContainer(ctx, cnr); err != nil {
		return nil, err
	}

	if err = n.pool.WaitForContainerPresence(ctx, bktInfo.CID, pool.DefaultPollingParams()); err != nil {
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
	if err := n.pool.SetEACL(ctx, table, n.SessionOpt(ctx)); err != nil {
		return err
	}

	return n.waitEACLPresence(ctx, cid, table, defaultWaitParams())
}

func (n *layer) GetContainerEACL(ctx context.Context, cid *cid.ID) (*eacl.Table, error) {
	signedEacl, err := n.pool.GetEACL(ctx, cid)
	if err != nil {
		return nil, err
	}
	return signedEacl.EACL(), nil
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

func (n *layer) waitEACLPresence(ctx context.Context, cid *cid.ID, table *eacl.Table, params *waitParams) error {
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
	for {
		select {
		case <-done:
			return ctx.Err()
		case <-wdone:
			return wctx.Err()
		case <-ticker.C:
			signedEacl, err := n.pool.GetEACL(ctx, cid)
			if err == nil {
				got, err := signedEacl.EACL().Marshal()
				if err == nil && bytes.Equal(exp, got) {
					return nil
				}
			}
			ticker.Reset(params.PollInterval)
		}
	}
}

func (n *layer) deleteContainer(ctx context.Context, cid *cid.ID) error {
	return n.pool.DeleteContainer(ctx, cid, n.SessionOpt(ctx))
}
