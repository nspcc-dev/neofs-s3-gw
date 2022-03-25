package neofs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	objectv2 "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/object/address"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

// NeoFS represents virtual connection to the NeoFS network.
// It is used to provide an interface to dependent packages
// which work with NeoFS.
type NeoFS struct {
	pool *pool.Pool
}

// NewNeoFS creates new NeoFS using provided pool.Pool.
func NewNeoFS(p *pool.Pool) *NeoFS {
	return &NeoFS{pool: p}
}

// TimeToEpoch implements neofs.NeoFS interface method.
func (x *NeoFS) TimeToEpoch(ctx context.Context, futureTime time.Time) (uint64, uint64, error) {
	now := time.Now()
	dur := futureTime.Sub(now)
	if dur < 0 {
		return 0, 0, fmt.Errorf("time '%s' must be in the future (after %s)",
			futureTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	conn, _, err := x.pool.Connection()
	if err != nil {
		return 0, 0, fmt.Errorf("get connection from pool: %w", err)
	}

	res, err := conn.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return 0, 0, fmt.Errorf("get network info via client: %w", err)
	}

	networkInfo := res.Info()
	var durEpoch uint64

	networkInfo.NetworkConfig().IterateParameters(func(parameter *netmap.NetworkParameter) bool {
		if string(parameter.Key()) == "EpochDuration" {
			data := make([]byte, 8)

			copy(data, parameter.Value())

			durEpoch = binary.LittleEndian.Uint64(data)

			return true
		}

		return false
	})

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
	res, err := x.pool.GetContainer(ctx, &idCnr)
	if err != nil {
		return nil, fmt.Errorf("read container via connection pool: %w", err)
	}

	return res, nil
}

// CreateContainer implements neofs.NeoFS interface method.
func (x *NeoFS) CreateContainer(ctx context.Context, prm neofs.PrmContainerCreate) (*cid.ID, error) {
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

	cnr := container.New(cnrOptions...)
	cnr.SetSessionToken(prm.SessionToken)

	if prm.Name != "" {
		container.SetNativeName(cnr, prm.Name)
	}

	// send request to save the container
	idCnr, err := x.pool.PutContainer(ctx, cnr)
	if err != nil {
		return nil, fmt.Errorf("save container via connection pool: %w", err)
	}

	// wait the container to be persisted
	err = x.pool.WaitForContainerPresence(ctx, idCnr, pool.DefaultPollingParams())
	if err != nil {
		return nil, fmt.Errorf("wait for container to be saved: %w", err)
	}

	return idCnr, nil
}

// UserContainers implements neofs.NeoFS interface method.
func (x *NeoFS) UserContainers(ctx context.Context, id owner.ID) ([]cid.ID, error) {
	r, err := x.pool.ListContainers(ctx, &id)
	if err != nil {
		return nil, fmt.Errorf("list user containers via connection pool: %w", err)
	}

	return r, nil
}

// SetContainerEACL implements neofs.NeoFS interface method.
func (x *NeoFS) SetContainerEACL(ctx context.Context, table eacl.Table) error {
	err := x.pool.SetEACL(ctx, &table)
	if err != nil {
		return fmt.Errorf("save eACL via connection pool: %w", err)
	}

	return err
}

// ContainerEACL implements neofs.NeoFS interface method.
func (x *NeoFS) ContainerEACL(ctx context.Context, id cid.ID) (*eacl.Table, error) {
	res, err := x.pool.GetEACL(ctx, &id)
	if err != nil {
		return nil, fmt.Errorf("read eACL via connection pool: %w", err)
	}

	return res, nil
}

// DeleteContainer implements neofs.NeoFS interface method.
func (x *NeoFS) DeleteContainer(ctx context.Context, id cid.ID, token *session.Token) error {
	err := x.pool.DeleteContainer(ctx, &id, pool.WithSession(token))
	if err != nil {
		return fmt.Errorf("delete container via connection pool: %w", err)
	}

	return nil
}

// CreateObject implements neofs.NeoFS interface method.
func (x *NeoFS) CreateObject(ctx context.Context, prm neofs.PrmObjectCreate) (*oid.ID, error) {
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
	obj.SetContainerID(&prm.Container)
	obj.SetOwnerID(&prm.Creator)
	obj.SetAttributes(attrs...)
	obj.SetPayloadSize(prm.PayloadSize)

	if len(prm.Locks) > 0 {
		lock := new(object.Lock)
		lock.WriteMembers(prm.Locks)
		objectv2.WriteLock(obj.ToV2(), (objectv2.Lock)(*lock))
	}

	var callOpt pool.CallOption

	if prm.BearerToken != nil {
		callOpt = pool.WithBearer(prm.BearerToken)
	} else {
		callOpt = pool.WithKey(prm.PrivateKey)
	}

	idObj, err := x.pool.PutObject(ctx, *obj, prm.Payload, callOpt)
	if err != nil {
		return nil, fmt.Errorf("save object via connection pool: %w", err)
	}

	return idObj, nil
}

// SelectObjects implements neofs.NeoFS interface method.
func (x *NeoFS) SelectObjects(ctx context.Context, prm neofs.PrmObjectSelect) ([]oid.ID, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()

	if prm.ExactAttribute[0] != "" {
		filters.AddFilter(prm.ExactAttribute[0], prm.ExactAttribute[1], object.MatchStringEqual)
	}

	if prm.FilePrefix != "" {
		filters.AddFilter(object.AttributeFileName, prm.FilePrefix, object.MatchCommonPrefix)
	}

	var callOpt pool.CallOption

	if prm.BearerToken != nil {
		callOpt = pool.WithBearer(prm.BearerToken)
	} else {
		callOpt = pool.WithKey(prm.PrivateKey)
	}

	res, err := x.pool.SearchObjects(ctx, prm.Container, filters, callOpt)
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
		// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
		if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
			return nil, neofs.ErrAccessDenied
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
		// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
		if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
			return n, neofs.ErrAccessDenied
		}
	}

	return n, err
}

// ReadObject implements neofs.NeoFS interface method.
func (x *NeoFS) ReadObject(ctx context.Context, prm neofs.PrmObjectRead) (*neofs.ObjectPart, error) {
	var addr address.Address
	addr.SetContainerID(&prm.Container)
	addr.SetObjectID(&prm.Object)

	var callOpt pool.CallOption

	if prm.BearerToken != nil {
		callOpt = pool.WithBearer(prm.BearerToken)
	} else {
		callOpt = pool.WithKey(prm.PrivateKey)
	}

	if prm.WithHeader {
		if prm.WithPayload {
			res, err := x.pool.GetObject(ctx, addr, callOpt)
			if err != nil {
				// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
				if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
					return nil, neofs.ErrAccessDenied
				}

				return nil, fmt.Errorf("init full object reading via connection pool: %w", err)
			}

			defer res.Payload.Close()

			payload, err := io.ReadAll(res.Payload)
			if err != nil {
				return nil, fmt.Errorf("read full object payload: %w", err)
			}

			res.Header.SetPayload(payload)

			return &neofs.ObjectPart{
				Head: &res.Header,
			}, nil
		}

		hdr, err := x.pool.HeadObject(ctx, addr, callOpt)
		if err != nil {
			// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
			if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
				return nil, neofs.ErrAccessDenied
			}

			return nil, fmt.Errorf("read object header via connection pool: %w", err)
		}

		return &neofs.ObjectPart{
			Head: hdr,
		}, nil
	} else if prm.PayloadRange[0]+prm.PayloadRange[1] == 0 {
		res, err := x.pool.GetObject(ctx, addr, callOpt)
		if err != nil {
			// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
			if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
				return nil, neofs.ErrAccessDenied
			}

			return nil, fmt.Errorf("init full payload range reading via connection pool: %w", err)
		}

		return &neofs.ObjectPart{
			Payload: res.Payload,
		}, nil
	}

	res, err := x.pool.ObjectRange(ctx, addr, prm.PayloadRange[0], prm.PayloadRange[1], callOpt)
	if err != nil {
		// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
		if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
			return nil, neofs.ErrAccessDenied
		}

		return nil, fmt.Errorf("init payload range reading via connection pool: %w", err)
	}

	return &neofs.ObjectPart{
		Payload: payloadReader{res},
	}, nil
}

// DeleteObject implements neofs.NeoFS interface method.
func (x *NeoFS) DeleteObject(ctx context.Context, prm neofs.PrmObjectDelete) error {
	var addr address.Address
	addr.SetContainerID(&prm.Container)
	addr.SetObjectID(&prm.Object)

	var callOpt pool.CallOption

	if prm.BearerToken != nil {
		callOpt = pool.WithBearer(prm.BearerToken)
	} else {
		callOpt = pool.WithKey(prm.PrivateKey)
	}

	err := x.pool.DeleteObject(ctx, addr, callOpt)
	if err != nil {
		// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
		if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
			return neofs.ErrAccessDenied
		}

		return fmt.Errorf("mark object removal via connection pool: %w", err)
	}

	return nil
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
	conn, _, err := x.pool.Connection()
	if err != nil {
		return "", fmt.Errorf("get connection from the pool: %w", err)
	}

	var prmCli client.PrmNetworkInfo

	res, err := conn.NetworkInfo(ctx, prmCli)
	if err != nil {
		return "", fmt.Errorf("read network info via client: %w", err)
	}

	var domain string

	res.Info().NetworkConfig().IterateParameters(func(parameter *netmap.NetworkParameter) bool {
		if string(parameter.Key()) == "SystemDNS" {
			domain = string(parameter.Value())
			return true
		}

		return false
	})

	if domain == "" {
		return "", errors.New("system DNS parameter not found or empty")
	}

	return domain, nil
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
	return x.neoFS.CreateContainer(ctx, neofs.PrmContainerCreate{
		Creator:  prm.Owner,
		Policy:   prm.Policy,
		Name:     prm.FriendlyName,
		BasicACL: 0b0011_1100_1000_1100_1000_1100_1100_1110, // 0x3C8C8CCE
	})
}

// ReadObjectPayload implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) ReadObjectPayload(ctx context.Context, addr address.Address) ([]byte, error) {
	res, err := x.neoFS.ReadObject(ctx, neofs.PrmObjectRead{
		Container:   *addr.ContainerID(),
		Object:      *addr.ObjectID(),
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
	return x.neoFS.CreateObject(ctx, neofs.PrmObjectCreate{
		Creator:   prm.Creator,
		Container: prm.Container,
		Filename:  prm.Filename,
		Attributes: [][2]string{
			{"__NEOFS__EXPIRATION_EPOCH", strconv.FormatUint(prm.ExpirationEpoch, 10)}},
		Payload: bytes.NewReader(prm.Payload),
	})
}
