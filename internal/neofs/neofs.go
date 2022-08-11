package neofs

import (
	"bytes"
	"context"
	"errors"
	stderrors "errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	objectv2 "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// NeoFS represents virtual connection to the NeoFS network.
// It is used to provide an interface to dependent packages
// which work with NeoFS.
type NeoFS struct {
	pool  *pool.Pool
	await pool.WaitParams
}

const (
	defaultPollInterval = time.Second       // overrides default value from pool
	defaultPollTimeout  = 120 * time.Second // same as default value from pool
)

// NewNeoFS creates new NeoFS using provided pool.Pool.
func NewNeoFS(p *pool.Pool) *NeoFS {
	var await pool.WaitParams
	await.SetPollInterval(defaultPollInterval)
	await.SetTimeout(defaultPollTimeout)

	return &NeoFS{
		pool:  p,
		await: await,
	}
}

// TimeToEpoch implements neofs.NeoFS interface method.
func (x *NeoFS) TimeToEpoch(ctx context.Context, futureTime time.Time) (uint64, uint64, error) {
	now := time.Now()
	dur := futureTime.Sub(now)
	if dur < 0 {
		return 0, 0, fmt.Errorf("time '%s' must be in the future (after %s)",
			futureTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	networkInfo, err := x.pool.NetworkInfo(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("get network info via client: %w", err)
	}

	durEpoch := networkInfo.EpochDuration()
	if durEpoch == 0 {
		return 0, 0, errors.New("epoch duration is missing or zero")
	}

	curr := networkInfo.CurrentEpoch()
	msPerEpoch := durEpoch * uint64(networkInfo.MsPerBlock())

	epochLifetime := uint64(dur.Milliseconds()) / msPerEpoch
	if uint64(dur.Milliseconds())%msPerEpoch != 0 {
		epochLifetime++
	}

	var epoch uint64
	if epochLifetime >= math.MaxUint64-curr {
		epoch = math.MaxUint64
	} else {
		epoch = curr + epochLifetime
	}

	return curr, epoch, nil
}

// Container implements neofs.NeoFS interface method.
func (x *NeoFS) Container(ctx context.Context, idCnr cid.ID) (*container.Container, error) {
	var prm pool.PrmContainerGet
	prm.SetContainerID(idCnr)

	res, err := x.pool.GetContainer(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("read container via connection pool: %w", err)
	}

	return res, nil
}

var basicACLZero acl.Basic

// CreateContainer implements neofs.NeoFS interface method.
//
// If prm.BasicACL is zero, 'eacl-public-read-write' is used.
func (x *NeoFS) CreateContainer(ctx context.Context, prm layer.PrmContainerCreate) (cid.ID, error) {
	if prm.BasicACL == basicACLZero {
		prm.BasicACL = acl.PublicRWExtended
	}

	var cnr container.Container
	cnr.Init()
	cnr.SetPlacementPolicy(prm.Policy)
	cnr.SetOwner(prm.Creator)
	cnr.SetBasicACL(prm.BasicACL)
	container.SetCreationTime(&cnr, time.Now())

	if prm.Name != "" {
		var d container.Domain
		d.SetName(prm.Name)

		container.WriteDomain(&cnr, d)
		container.SetName(&cnr, prm.Name)
	}

	for i := range prm.AdditionalAttributes {
		cnr.SetAttribute(prm.AdditionalAttributes[i][0], prm.AdditionalAttributes[i][1])
	}

	err := pool.SyncContainerWithNetwork(ctx, &cnr, x.pool)
	if err != nil {
		return cid.ID{}, fmt.Errorf("sync container with the network state: %w", err)
	}

	var prmPut pool.PrmContainerPut
	prmPut.SetContainer(cnr)
	prmPut.SetWaitParams(x.await)

	if prm.SessionToken != nil {
		prmPut.WithinSession(*prm.SessionToken)
	}

	// send request to save the container
	idCnr, err := x.pool.PutContainer(ctx, prmPut)
	if err != nil {
		return cid.ID{}, fmt.Errorf("save container via connection pool: %w", err)
	}

	return *idCnr, nil
}

// UserContainers implements neofs.NeoFS interface method.
func (x *NeoFS) UserContainers(ctx context.Context, id user.ID) ([]cid.ID, error) {
	var prm pool.PrmContainerList
	prm.SetOwnerID(id)

	r, err := x.pool.ListContainers(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("list user containers via connection pool: %w", err)
	}

	return r, nil
}

// SetContainerEACL implements neofs.NeoFS interface method.
func (x *NeoFS) SetContainerEACL(ctx context.Context, table eacl.Table, sessionToken *session.Container) error {
	var prm pool.PrmContainerSetEACL
	prm.SetTable(table)
	prm.SetWaitParams(x.await)

	if sessionToken != nil {
		prm.WithinSession(*sessionToken)
	}

	err := x.pool.SetEACL(ctx, prm)
	if err != nil {
		return fmt.Errorf("save eACL via connection pool: %w", err)
	}

	return err
}

// ContainerEACL implements neofs.NeoFS interface method.
func (x *NeoFS) ContainerEACL(ctx context.Context, id cid.ID) (*eacl.Table, error) {
	var prm pool.PrmContainerEACL
	prm.SetContainerID(id)

	res, err := x.pool.GetEACL(ctx, prm)
	if err != nil {
		return nil, fmt.Errorf("read eACL via connection pool: %w", err)
	}

	return res, nil
}

// DeleteContainer implements neofs.NeoFS interface method.
func (x *NeoFS) DeleteContainer(ctx context.Context, id cid.ID, token *session.Container) error {
	var prm pool.PrmContainerDelete
	prm.SetContainerID(id)
	prm.SetWaitParams(x.await)

	if token != nil {
		prm.SetSessionToken(*token)
	}

	err := x.pool.DeleteContainer(ctx, prm)
	if err != nil {
		return fmt.Errorf("delete container via connection pool: %w", err)
	}

	return nil
}

// CreateObject implements neofs.NeoFS interface method.
func (x *NeoFS) CreateObject(ctx context.Context, prm layer.PrmObjectCreate) (oid.ID, error) {
	attrNum := len(prm.Attributes) + 1 // + creation time

	if prm.Filename != "" {
		attrNum++
	}

	attrs := make([]object.Attribute, 0, attrNum)
	var a *object.Attribute

	a = object.NewAttribute()
	a.SetKey(object.AttributeTimestamp)
	a.SetValue(strconv.FormatInt(time.Now().Unix(), 10))
	attrs = append(attrs, *a)

	for i := range prm.Attributes {
		a = object.NewAttribute()
		a.SetKey(prm.Attributes[i][0])
		a.SetValue(prm.Attributes[i][1])
		attrs = append(attrs, *a)
	}

	if prm.Filename != "" {
		a = object.NewAttribute()
		a.SetKey(object.AttributeFileName)
		a.SetValue(prm.Filename)
		attrs = append(attrs, *a)
	}

	obj := object.New()
	obj.SetContainerID(prm.Container)
	obj.SetOwnerID(&prm.Creator)
	obj.SetAttributes(attrs...)
	obj.SetPayloadSize(prm.PayloadSize)

	if len(prm.Locks) > 0 {
		lock := new(object.Lock)
		lock.WriteMembers(prm.Locks)
		objectv2.WriteLock(obj.ToV2(), (objectv2.Lock)(*lock))
	}

	var prmPut pool.PrmObjectPut
	prmPut.SetHeader(*obj)
	prmPut.SetPayload(prm.Payload)

	if prm.BearerToken != nil {
		prmPut.UseBearer(*prm.BearerToken)
	} else {
		prmPut.UseKey(prm.PrivateKey)
	}

	idObj, err := x.pool.PutObject(ctx, prmPut)
	if err != nil {
		reason, ok := isErrAccessDenied(err)
		if ok {
			return oid.ID{}, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}
		return oid.ID{}, fmt.Errorf("save object via connection pool: %w", err)
	}

	return *idObj, nil
}

// SelectObjects implements neofs.NeoFS interface method.
func (x *NeoFS) SelectObjects(ctx context.Context, prm layer.PrmObjectSelect) ([]oid.ID, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()

	if prm.ExactAttribute[0] != "" {
		filters.AddFilter(prm.ExactAttribute[0], prm.ExactAttribute[1], object.MatchStringEqual)
	}

	if prm.FilePrefix != "" {
		filters.AddFilter(object.AttributeFileName, prm.FilePrefix, object.MatchCommonPrefix)
	}

	var prmSearch pool.PrmObjectSearch
	prmSearch.SetContainerID(prm.Container)
	prmSearch.SetFilters(filters)

	if prm.BearerToken != nil {
		prmSearch.UseBearer(*prm.BearerToken)
	} else {
		prmSearch.UseKey(prm.PrivateKey)
	}

	res, err := x.pool.SearchObjects(ctx, prmSearch)
	if err != nil {
		return nil, fmt.Errorf("init object search via connection pool: %w", err)
	}

	defer res.Close()

	var buf []oid.ID

	err = res.Iterate(func(id oid.ID) bool {
		buf = append(buf, id)
		return false
	})
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}

		return nil, fmt.Errorf("read object list: %w", err)
	}

	return buf, nil
}

// wraps io.ReadCloser and transforms Read errors related to access violation
// to neofs.ErrAccessDenied.
type payloadReader struct {
	io.ReadCloser
}

func (x payloadReader) Read(p []byte) (int, error) {
	n, err := x.ReadCloser.Read(p)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return n, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}
	}

	return n, err
}

// ReadObject implements neofs.NeoFS interface method.
func (x *NeoFS) ReadObject(ctx context.Context, prm layer.PrmObjectRead) (*layer.ObjectPart, error) {
	var addr oid.Address
	addr.SetContainer(prm.Container)
	addr.SetObject(prm.Object)

	var prmGet pool.PrmObjectGet
	prmGet.SetAddress(addr)

	if prm.BearerToken != nil {
		prmGet.UseBearer(*prm.BearerToken)
	} else {
		prmGet.UseKey(prm.PrivateKey)
	}

	if prm.WithHeader {
		if prm.WithPayload {
			res, err := x.pool.GetObject(ctx, prmGet)
			if err != nil {
				if reason, ok := isErrAccessDenied(err); ok {
					return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
				}

				return nil, fmt.Errorf("init full object reading via connection pool: %w", err)
			}

			defer res.Payload.Close()

			payload, err := io.ReadAll(res.Payload)
			if err != nil {
				return nil, fmt.Errorf("read full object payload: %w", err)
			}

			res.Header.SetPayload(payload)

			return &layer.ObjectPart{
				Head: &res.Header,
			}, nil
		}

		var prmHead pool.PrmObjectHead
		prmHead.SetAddress(addr)

		if prm.BearerToken != nil {
			prmHead.UseBearer(*prm.BearerToken)
		} else {
			prmHead.UseKey(prm.PrivateKey)
		}

		hdr, err := x.pool.HeadObject(ctx, prmHead)
		if err != nil {
			if reason, ok := isErrAccessDenied(err); ok {
				return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
			}

			return nil, fmt.Errorf("read object header via connection pool: %w", err)
		}

		return &layer.ObjectPart{
			Head: hdr,
		}, nil
	} else if prm.PayloadRange[0]+prm.PayloadRange[1] == 0 {
		res, err := x.pool.GetObject(ctx, prmGet)
		if err != nil {
			if reason, ok := isErrAccessDenied(err); ok {
				return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
			}

			return nil, fmt.Errorf("init full payload range reading via connection pool: %w", err)
		}

		return &layer.ObjectPart{
			Payload: res.Payload,
		}, nil
	}

	var prmRange pool.PrmObjectRange
	prmRange.SetAddress(addr)
	prmRange.SetOffset(prm.PayloadRange[0])
	prmRange.SetLength(prm.PayloadRange[1])

	if prm.BearerToken != nil {
		prmRange.UseBearer(*prm.BearerToken)
	} else {
		prmRange.UseKey(prm.PrivateKey)
	}

	res, err := x.pool.ObjectRange(ctx, prmRange)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}

		return nil, fmt.Errorf("init payload range reading via connection pool: %w", err)
	}

	return &layer.ObjectPart{
		Payload: payloadReader{res},
	}, nil
}

// DeleteObject implements neofs.NeoFS interface method.
func (x *NeoFS) DeleteObject(ctx context.Context, prm layer.PrmObjectDelete) error {
	var addr oid.Address
	addr.SetContainer(prm.Container)
	addr.SetObject(prm.Object)

	var prmDelete pool.PrmObjectDelete
	prmDelete.SetAddress(addr)

	if prm.BearerToken != nil {
		prmDelete.UseBearer(*prm.BearerToken)
	} else {
		prmDelete.UseKey(prm.PrivateKey)
	}

	err := x.pool.DeleteObject(ctx, prmDelete)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}

		return fmt.Errorf("mark object removal via connection pool: %w", err)
	}

	return nil
}

func (x *NeoFS) AstToTable(ast *handler.Ast) (*eacl.Table, error) {
	table := eacl.NewTable()

	for i := len(ast.Resources) - 1; i >= 0; i-- {
		records, err := formRecords(ast.Resources[i])
		if err != nil {
			return nil, fmt.Errorf("form records: %w", err)
		}

		serviceRecord := serviceRecord{
			Resource:           ast.Resources[i].Name(),
			GroupRecordsLength: len(records),
		}
		table.AddRecord(serviceRecord.ToEACLRecord())

		for _, rec := range records {
			table.AddRecord(rec)
		}
	}

	return table, nil
}

func (x *NeoFS) TableToAst(table *eacl.Table, bktName string) *handler.Ast {
	resourceMap := make(map[string]orderedAstResource)

	var groupRecordsLeft int
	var currentResource orderedAstResource
	for i, record := range table.Records() {
		if serviceRec := tryServiceRecord(record); serviceRec != nil {
			resInfo := handler.ResourceInfoFromName(serviceRec.Resource, bktName)
			groupRecordsLeft = serviceRec.GroupRecordsLength

			currentResource = getResourceOrCreate(resourceMap, i, resInfo)
			resourceMap[resInfo.Name()] = currentResource
		} else if groupRecordsLeft != 0 {
			groupRecordsLeft--
			addOperationsAndUpdateMap(currentResource, record, resourceMap)
		} else {
			resInfo := resInfoFromFilters(bktName, record.Filters())
			resource := getResourceOrCreate(resourceMap, i, resInfo)
			addOperationsAndUpdateMap(resource, record, resourceMap)
		}
	}

	return &handler.Ast{
		Resources: formReverseOrderResources(resourceMap),
	}
}

func (x *NeoFS) BucketACLToTable(acp *handler.AccessControlPolicy, resInfo *handler.ResourceInfo) (*eacl.Table, error) {
	if !resInfo.IsBucket() {
		return nil, fmt.Errorf("allowed only bucket acl")
	}

	var found bool
	table := eacl.NewTable()

	ownerKey, err := keys.NewPublicKeyFromString(acp.Owner.ID)
	if err != nil {
		return nil, fmt.Errorf("public key from string: %w", err)
	}

	for _, grant := range acp.AccessControlList {
		if !isValidGrant(grant) {
			return nil, stderrors.New("unsupported grantee")
		}
		if grant.Grantee.ID == acp.Owner.ID {
			found = true
		}

		getRecord, err := getRecordFunction(grant.Grantee)
		if err != nil {
			return nil, fmt.Errorf("record func from grantee: %w", err)
		}
		for _, op := range permissionToOperations(grant.Permission) {
			table.AddRecord(getRecord(op))
		}
	}

	if !found {
		for _, op := range handler.FullOps {
			table.AddRecord(getAllowRecord(op, ownerKey))
		}
	}

	for _, op := range handler.FullOps {
		table.AddRecord(getOthersRecord(op, eacl.ActionDeny))
	}

	return table, nil
}

func isErrAccessDenied(err error) (string, bool) {
	unwrappedErr := errors.Unwrap(err)
	for unwrappedErr != nil {
		err = unwrappedErr
		unwrappedErr = errors.Unwrap(err)
	}

	switch err := err.(type) {
	default:
		return "", false
	case apistatus.ObjectAccessDenied:
		return err.Reason(), true
	case *apistatus.ObjectAccessDenied:
		return err.Reason(), true
	}
}

// ResolverNeoFS represents virtual connection to the NeoFS network.
// It implements resolver.NeoFS.
type ResolverNeoFS struct {
	pool *pool.Pool
}

// NewResolverNeoFS creates new ResolverNeoFS using provided pool.Pool.
func NewResolverNeoFS(p *pool.Pool) *ResolverNeoFS {
	return &ResolverNeoFS{pool: p}
}

// SystemDNS implements resolver.NeoFS interface method.
func (x *ResolverNeoFS) SystemDNS(ctx context.Context) (string, error) {
	networkInfo, err := x.pool.NetworkInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("read network info via client: %w", err)
	}

	domain := networkInfo.RawNetworkParameter("SystemDNS")
	if domain == nil {
		return "", errors.New("system DNS parameter not found or empty")
	}

	return string(domain), nil
}

// AuthmateNeoFS is a mediator which implements authmate.NeoFS through pool.Pool.
type AuthmateNeoFS struct {
	neoFS *NeoFS
}

// NewAuthmateNeoFS creates new AuthmateNeoFS using provided pool.Pool.
func NewAuthmateNeoFS(p *pool.Pool) *AuthmateNeoFS {
	return &AuthmateNeoFS{neoFS: NewNeoFS(p)}
}

// ContainerExists implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) ContainerExists(ctx context.Context, idCnr cid.ID) error {
	_, err := x.neoFS.Container(ctx, idCnr)
	if err != nil {
		return fmt.Errorf("get container via connection pool: %w", err)
	}

	return nil
}

// TimeToEpoch implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) TimeToEpoch(ctx context.Context, futureTime time.Time) (uint64, uint64, error) {
	return x.neoFS.TimeToEpoch(ctx, futureTime)
}

// CreateContainer implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) CreateContainer(ctx context.Context, prm authmate.PrmContainerCreate) (cid.ID, error) {
	basicACL := acl.Private
	// allow reading objects to OTHERS in order to provide read access to S3 gateways
	basicACL.AllowOp(acl.OpObjectGet, acl.RoleOthers)

	return x.neoFS.CreateContainer(ctx, layer.PrmContainerCreate{
		Creator:  prm.Owner,
		Policy:   prm.Policy,
		Name:     prm.FriendlyName,
		BasicACL: basicACL,
	})
}

// ReadObjectPayload implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) ReadObjectPayload(ctx context.Context, addr oid.Address) ([]byte, error) {
	res, err := x.neoFS.ReadObject(ctx, layer.PrmObjectRead{
		Container:   addr.Container(),
		Object:      addr.Object(),
		WithPayload: true,
	})
	if err != nil {
		return nil, err
	}

	defer res.Payload.Close()

	return io.ReadAll(res.Payload)
}

// CreateObject implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) CreateObject(ctx context.Context, prm tokens.PrmObjectCreate) (oid.ID, error) {
	return x.neoFS.CreateObject(ctx, layer.PrmObjectCreate{
		Creator:   prm.Creator,
		Container: prm.Container,
		Filename:  prm.Filename,
		Attributes: [][2]string{
			{"__NEOFS__EXPIRATION_EPOCH", strconv.FormatUint(prm.ExpirationEpoch, 10)}},
		Payload: bytes.NewReader(prm.Payload),
	})
}

// PoolStatistic is a mediator which implements authmate.NeoFS through pool.Pool.
type PoolStatistic struct {
	pool *pool.Pool
}

// NewPoolStatistic creates new PoolStatistic using provided pool.Pool.
func NewPoolStatistic(p *pool.Pool) *PoolStatistic {
	return &PoolStatistic{pool: p}
}

// Statistic implements interface method.
func (x *PoolStatistic) Statistic() pool.Statistic {
	return x.pool.Statistic()
}
