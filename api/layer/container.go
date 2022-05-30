package layer

import (
	"context"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/errors"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	"github.com/nspcc-dev/neofs-sdk-go/client"
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

const (
	attributeLocationConstraint = ".s3-location-constraint"
	AttributeLockEnabled        = "LockEnabled"
)

func (n *layer) containerInfo(ctx context.Context, idCnr cid.ID) (*data.BucketInfo, error) {
	var (
		err error
		res *container.Container
		rid = api.GetRequestID(ctx)
		log = n.log.With(zap.Stringer("cid", idCnr), zap.String("request_id", rid))

		info = &data.BucketInfo{
			CID:  idCnr,
			Name: idCnr.EncodeToString(),
		}
	)
	res, err = n.neoFS.Container(ctx, idCnr)
	if err != nil {
		log.Error("could not fetch container", zap.Error(err))

		if client.IsErrContainerNotFound(err) {
			return nil, errors.GetAPIError(errors.ErrNoSuchBucket)
		}
		return nil, err
	}

	info.Owner = *res.OwnerID()
	info.BasicACL = res.BasicACL()

	for _, attr := range res.Attributes() {
		switch key, val := attr.Key(), attr.Value(); key {
		case container.AttributeName:
			info.Name = val
		case container.AttributeTimestamp:
			unix, err := strconv.ParseInt(attr.Value(), 10, 64)
			if err != nil {
				log.Error("could not parse container creation time",
					zap.String("created_at", val), zap.Error(err))

				continue
			}

			info.Created = time.Unix(unix, 0)
		case attributeLocationConstraint:
			info.LocationConstraint = val
		case AttributeLockEnabled:
			info.ObjectLockEnabled, err = strconv.ParseBool(val)
			if err != nil {
				log.Error("could not parse container object lock enabled attribute",
					zap.String("lock_enabled", val), zap.Error(err))
			}
		}
	}

	if err = n.bucketCache.Put(info); err != nil {
		log.Warn("could not put bucket info into cache",
			zap.String("bucket_name", info.Name), zap.Error(err))
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
	res, err = n.neoFS.UserContainers(ctx, own)
	if err != nil {
		n.log.Error("could not list user containers",
			zap.String("request_id", rid),
			zap.Error(err))
		return nil, err
	}

	list := make([]*data.BucketInfo, 0, len(res))
	for i := range res {
		info, err := n.containerInfo(ctx, res[i])
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

func (n *layer) createContainer(ctx context.Context, p *CreateBucketParams) (*data.BucketInfo, error) {
	var err error
	ownerID := n.Owner(ctx)
	if p.LocationConstraint == "" {
		p.LocationConstraint = api.DefaultLocationConstraint // s3tests_boto3.functional.test_s3:test_bucket_get_location
	}
	bktInfo := &data.BucketInfo{
		Name:               p.Name,
		Owner:              ownerID,
		Created:            time.Now(), // this can be a little incorrect since the real time is set later
		BasicACL:           p.ACL,
		LocationConstraint: p.LocationConstraint,
		ObjectLockEnabled:  p.ObjectLockEnabled,
	}

	var attributes [][2]string

	attributes = append(attributes, [2]string{
		attributeLocationConstraint, p.LocationConstraint,
	})

	if p.ObjectLockEnabled {
		attributes = append(attributes, [2]string{
			AttributeLockEnabled, "true",
		})
	}

	idCnr, err := n.neoFS.CreateContainer(ctx, neofs.PrmContainerCreate{
		Creator:              bktInfo.Owner,
		Policy:               *p.Policy,
		Name:                 p.Name,
		SessionToken:         p.SessionToken,
		BasicACL:             acl.BasicACL(p.ACL),
		AdditionalAttributes: attributes,
	})
	if err != nil {
		return nil, err
	}

	bktInfo.CID = *idCnr

	if err = n.setContainerEACLTable(ctx, bktInfo.CID, p.EACL); err != nil {
		return nil, err
	}

	if err = n.bucketCache.Put(bktInfo); err != nil {
		n.log.Warn("couldn't put bucket info into cache",
			zap.String("bucket name", bktInfo.Name),
			zap.Stringer("bucket cid", bktInfo.CID),
			zap.Error(err))
	}

	return bktInfo, nil
}

func (n *layer) setContainerEACLTable(ctx context.Context, idCnr cid.ID, table *eacl.Table) error {
	table.SetCID(idCnr)

	boxData, err := GetBoxData(ctx)
	if err == nil {
		table.SetSessionToken(boxData.Gate.SessionTokenForSetEACL())
	}

	return n.neoFS.SetContainerEACL(ctx, *table)
}

func (n *layer) GetContainerEACL(ctx context.Context, idCnr cid.ID) (*eacl.Table, error) {
	return n.neoFS.ContainerEACL(ctx, idCnr)
}

func (n *layer) deleteContainer(ctx context.Context, idCnr cid.ID) error {
	var sessionToken *session.Container
	boxData, err := GetBoxData(ctx)
	if err == nil {
		sessionToken = boxData.Gate.SessionTokenForDelete()
	}

	return n.neoFS.DeleteContainer(ctx, idCnr, sessionToken)
}
