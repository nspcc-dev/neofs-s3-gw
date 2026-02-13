package layer

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
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
		rid = api.GetContextRequestID(ctx)
		log = n.log.With(zap.Stringer("cid", idCnr), zap.String("request_id", rid))

		info = &data.BucketInfo{
			CID:  idCnr,
			Name: idCnr.EncodeToString(),
		}
	)
	res, err = n.neoFS.Container(ctx, idCnr)
	if err != nil {
		log.Error("could not fetch container", zap.Error(err))

		if errors.Is(err, apistatus.ErrContainerNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchBucket)
		}
		return nil, fmt.Errorf("get neofs container: %w", err)
	}

	cnr := *res

	info.Owner = cnr.Owner()
	if domain := cnr.ReadDomain(); domain.Name() != "" {
		info.Name = domain.Name()
	}
	info.Created = cnr.CreatedAt()
	info.LocationConstraint = cnr.Attribute(attributeLocationConstraint)
	info.AttributeCors = cnr.Attribute(attributeCors)
	info.AttributeTags = cnr.Attribute(attributeTags)
	info.AttributeSettings = cnr.Attribute(attributeSettings)
	info.AttributeNotifications = cnr.Attribute(attributeNotifications)

	attrLockEnabled := cnr.Attribute(AttributeLockEnabled)
	if len(attrLockEnabled) > 0 {
		info.ObjectLockEnabled, err = strconv.ParseBool(attrLockEnabled)
		if err != nil {
			log.Error("could not parse container object lock enabled attribute",
				zap.String("lock_enabled", attrLockEnabled),
				zap.Error(err),
			)
		}
	}

	n.cache.PutBucket(info)

	return info, nil
}

func (n *layer) containerList(ctx context.Context) ([]*data.BucketInfo, error) {
	var (
		err error
		own = n.Owner(ctx)
		res []cid.ID
		rid = api.GetContextRequestID(ctx)
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
	ownerID := n.Owner(ctx)
	if p.LocationConstraint == "" {
		p.LocationConstraint = api.DefaultLocationConstraint // s3tests_boto3.functional.test_s3:test_bucket_get_location
	}

	bktInfo := &data.BucketInfo{
		Name:               p.Name,
		Owner:              ownerID,
		Created:            TimeNow(ctx),
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

	idCnr, err := n.neoFS.CreateContainerAndSetEACL(ctx, PrmContainerCreate{
		Creator:              bktInfo.Owner,
		Policy:               p.Policy,
		Name:                 p.Name,
		SessionToken:         p.SessionContainerCreation,
		CreationTime:         bktInfo.Created,
		AdditionalAttributes: attributes,
	}, *p.EACL, p.SessionEACL)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}

	bktInfo.CID = idCnr
	p.EACL.SetCID(idCnr)

	n.cache.PutBucket(bktInfo)
	n.cache.PutBucketACL(bktInfo.CID, p.EACL)

	return bktInfo, nil
}

func (n *layer) setContainerEACLTable(ctx context.Context, idCnr cid.ID, table *eacl.Table, sessionToken *session.Container) error {
	table.SetCID(idCnr)

	err := n.neoFS.SetContainerEACL(ctx, *table, sessionToken)
	if err == nil {
		n.cache.PutBucketACL(idCnr, table)
	}

	return err
}

func (n *layer) GetContainerEACL(ctx context.Context, idCnr cid.ID) (*eacl.Table, error) {
	return n.neoFS.ContainerEACL(ctx, idCnr)
}
