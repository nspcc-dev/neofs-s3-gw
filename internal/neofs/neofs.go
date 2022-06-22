package neofs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/vm/stackitem"
	objectv2 "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
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

// CreateContainer implements neofs.NeoFS interface method.
//
// If prm.BasicACL is zero, 'eacl-public-read-write' is used.
func (x *NeoFS) CreateContainer(ctx context.Context, prm layer.PrmContainerCreate) (*cid.ID, error) {
	if prm.BasicACL == 0 {
		prm.BasicACL = acl.EACLPublicBasicRule
	}

	// fill container structure
	cnrOptions := []container.Option{
		container.WithPolicy(&prm.Policy),
		container.WithOwnerID(&prm.Creator),
		container.WithCustomBasicACL(prm.BasicACL),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)),
	}

	if prm.Name != "" {
		cnrOptions = append(cnrOptions, container.WithAttribute(container.AttributeName, prm.Name))
	}

	for _, attr := range prm.AdditionalAttributes {
		cnrOptions = append(cnrOptions, container.WithAttribute(attr[0], attr[1]))
	}

	// https://github.com/nspcc-dev/neofs-s3-gw/issues/435
	// environment without hh disabling feature will ignore this attribute
	// environment with hh disabling feature will set disabling = true if network config says so
	if hhDisabled, err := isHomomorphicHashDisabled(ctx, x.pool); err != nil {
		return nil, err
	} else if hhDisabled {
		cnrOptions = append(cnrOptions, container.WithAttribute(
			"__NEOFS__DISABLE_HOMOMORPHIC_HASHING", "true"))
	}

	cnr := container.New(cnrOptions...)

	if prm.Name != "" {
		container.SetNativeName(cnr, prm.Name)
	}

	var prmPut pool.PrmContainerPut
	prmPut.SetContainer(*cnr)
	prmPut.SetWaitParams(x.await)

	if prm.SessionToken != nil {
		prmPut.WithinSession(*prm.SessionToken)
	}

	// send request to save the container
	idCnr, err := x.pool.PutContainer(ctx, prmPut)
	if err != nil {
		return nil, fmt.Errorf("save container via connection pool: %w", err)
	}

	return idCnr, nil
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
func (x *NeoFS) CreateObject(ctx context.Context, prm layer.PrmObjectCreate) (*oid.ID, error) {
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
		return nil, fmt.Errorf("save object via connection pool: %w", err)
	}

	return idObj, nil
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

func isErrAccessDenied(err error) (string, bool) {
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
func (x *AuthmateNeoFS) CreateContainer(ctx context.Context, prm authmate.PrmContainerCreate) (*cid.ID, error) {
	return x.neoFS.CreateContainer(ctx, layer.PrmContainerCreate{
		Creator:  prm.Owner,
		Policy:   prm.Policy,
		Name:     prm.FriendlyName,
		BasicACL: 0b0011_1100_1000_1100_1000_1100_1100_1110, // 0x3C8C8CCE
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
func (x *AuthmateNeoFS) CreateObject(ctx context.Context, prm tokens.PrmObjectCreate) (*oid.ID, error) {
	return x.neoFS.CreateObject(ctx, layer.PrmObjectCreate{
		Creator:   prm.Creator,
		Container: prm.Container,
		Filename:  prm.Filename,
		Attributes: [][2]string{
			{"__NEOFS__EXPIRATION_EPOCH", strconv.FormatUint(prm.ExpirationEpoch, 10)}},
		Payload: bytes.NewReader(prm.Payload),
	})
}

func isHomomorphicHashDisabled(ctx context.Context, p *pool.Pool) (bool, error) {
	ni, err := p.NetworkInfo(ctx)
	if err != nil {
		return false, err
	}

	// FIXME(@cthulhu-rider): parameter format hasn't been fixed in the protocol yet,
	//  use decoding  provided by SDK after neofs-api#214 support.
	rawPrm := ni.RawNetworkParameter("HomomorphicHashingDisabled")
	if rawPrm != nil {
		return stackitem.NewByteArray(rawPrm).TryBool()
	}

	return false, nil
}
