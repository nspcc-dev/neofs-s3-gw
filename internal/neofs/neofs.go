package neofs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
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
	"github.com/nspcc-dev/neofs-sdk-go/token"
)

// NeoFS represents virtual connection to the NeoFS network.
// It is used to provide an interface to dependent packages
// which work with NeoFS.
type NeoFS struct {
	pool pool.Pool
}

// SetConnectionPool binds underlying pool.Pool. Must be
// called on initialization stage before any usage.
func (x *NeoFS) SetConnectionPool(p pool.Pool) {
	x.pool = p
}

// NetworkState implements authmate.NeoFS interface method.
func (x *NeoFS) NetworkState(ctx context.Context) (*authmate.NetworkState, error) {
	conn, _, err := x.pool.Connection()
	if err != nil {
		return nil, fmt.Errorf("get connection from pool: %w", err)
	}

	res, err := conn.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return nil, fmt.Errorf("get network info via client: %w", err)
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
		return nil, errors.New("epoch duration is missing or zero")
	}

	return &authmate.NetworkState{
		Epoch:         networkInfo.CurrentEpoch(),
		BlockDuration: networkInfo.MsPerBlock(),
		EpochDuration: durEpoch,
	}, nil
}

// Container reads container by ID using connection pool. Returns exact one non-nil value.
func (x *NeoFS) Container(ctx context.Context, idCnr cid.ID) (*container.Container, error) {
	res, err := x.pool.GetContainer(ctx, &idCnr)
	if err != nil {
		return nil, fmt.Errorf("read container via connection pool: %w", err)
	}

	return res, nil
}

// ContainerExists implements authmate.NeoFS interface method.
func (x *NeoFS) ContainerExists(ctx context.Context, idCnr cid.ID) error {
	_, err := x.pool.GetContainer(ctx, &idCnr)
	if err != nil {
		return fmt.Errorf("get container via connection pool: %w", err)
	}

	return nil
}

// PrmContainerCreate groups parameters of CreateContainer operation.
type PrmContainerCreate struct {
	// NeoFS identifier of the container creator.
	Creator owner.ID

	// Container placement policy.
	Policy netmap.PlacementPolicy

	// Name for the container.
	Name string

	// Time when container is created.
	Time time.Time

	// Basic ACL of the container.
	BasicACL acl.BasicACL

	// Token of the container's creation session (optional, nil means session absence).
	SessionToken *session.Token

	// Attribute for LocationConstraint parameter (optional).
	LocationConstraintAttribute *container.Attribute
}

// CreateContainer constructs new container from the parameters and saves it in NeoFS
// using connection pool. Returns any error encountered which prevent the container
// to be saved.
func (x *NeoFS) CreateContainer(ctx context.Context, prm PrmContainerCreate) (*cid.ID, error) {
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

	if prm.LocationConstraintAttribute != nil {
		cnrOptions = append(cnrOptions, container.WithAttribute(
			prm.LocationConstraintAttribute.Key(),
			prm.LocationConstraintAttribute.Value(),
		))
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

// UserContainers reads list of user containers from NeoFS using connection pool.
// Returns any error encountered which prevent the containers to be listed.
func (x *NeoFS) UserContainers(ctx context.Context, id owner.ID) ([]cid.ID, error) {
	r, err := x.pool.ListContainers(ctx, &id)
	if err != nil {
		return nil, fmt.Errorf("list user containers via connection pool: %w", err)
	}

	res := make([]cid.ID, len(r))
	for i := range r {
		res[i] = *r[i]
	}

	return res, nil
}

// SetContainerEACL saves eACL table of the container in NeoFS using connection pool.
// Returns any error encountered which prevented the eACL to be saved.
func (x *NeoFS) SetContainerEACL(ctx context.Context, table eacl.Table) error {
	err := x.pool.SetEACL(ctx, &table)
	if err != nil {
		return fmt.Errorf("save eACL via connection pool: %w", err)
	}

	return err
}

// ContainerEACL reads eACL table of the container from NeoFS using connection pool.
// Returns any error encountered which prevented the eACL to be read.
func (x *NeoFS) ContainerEACL(ctx context.Context, id cid.ID) (*eacl.Table, error) {
	res, err := x.pool.GetEACL(ctx, &id)
	if err != nil {
		return nil, fmt.Errorf("read eACL via connection pool: %w", err)
	}

	return res, nil
}

// DeleteContainer marks container to be removed from NeoFS using connection pool.
// Returns any error encountered which prevented removal request to be sent.
func (x *NeoFS) DeleteContainer(ctx context.Context, id cid.ID, token *session.Token) error {
	err := x.pool.DeleteContainer(ctx, &id, pool.WithSession(token))
	if err != nil {
		return fmt.Errorf("delete container via connection pool: %w", err)
	}

	return nil
}

type PrmObjectCreate struct {
	// NeoFS identifier of the object creator.
	Creator owner.ID

	// NeoFS container to store the object.
	Container cid.ID

	// Object creation time.
	Time time.Time

	// Associated filename (optional).
	Filename string

	// Last NeoFS epoch of the object lifetime (optional).
	ExpirationEpoch uint64

	// Full payload size (optional).
	PayloadSize uint64

	// Key-value object attributes.
	Attributes [][2]string

	// Object payload encapsulated in io.Reader primitive.
	Payload io.Reader

	// Bearer token to be used for the operation. Overlaps PrivateKey. Optional.
	BearerToken *token.BearerToken

	// Private key used for the operation if BearerToken is missing (in this case non-nil).
	PrivateKey *ecdsa.PrivateKey
}

// CreateObject creates and saves a parameterized object in the specified
// NeoFS container from a specific user. Returns ID of the saved object.
//
// Returns exactly one non-nil value. Returns any error encountered which
// prevented the object to be created.
func (x *NeoFS) CreateObject(ctx context.Context, prm PrmObjectCreate) (*oid.ID, error) {
	attrNum := len(prm.Attributes) + 1 // + creation time

	if prm.Filename != "" {
		attrNum++
	}

	if prm.ExpirationEpoch > 0 {
		attrNum++
	}

	attrs := make([]*object.Attribute, 0, attrNum)
	var a *object.Attribute

	a = object.NewAttribute()
	a.SetKey(object.AttributeTimestamp)
	a.SetValue(strconv.FormatInt(prm.Time.Unix(), 10))
	attrs = append(attrs, a)

	for i := range prm.Attributes {
		a = object.NewAttribute()
		a.SetKey(prm.Attributes[i][0])
		a.SetValue(prm.Attributes[i][1])
		attrs = append(attrs, a)
	}

	if prm.Filename != "" {
		a = object.NewAttribute()
		a.SetKey(object.AttributeFileName)
		a.SetValue(prm.Filename)
		attrs = append(attrs, a)
	}

	if prm.ExpirationEpoch > 0 {
		a = object.NewAttribute()
		a.SetKey("__NEOFS__EXPIRATION_EPOCH")
		a.SetValue(strconv.FormatUint(prm.ExpirationEpoch, 10))
		attrs = append(attrs, a)
	}

	raw := object.NewRaw()
	raw.SetContainerID(&prm.Container)
	raw.SetOwnerID(&prm.Creator)
	raw.SetAttributes(attrs...)
	raw.SetPayloadSize(prm.PayloadSize)

	var callOpt pool.CallOption

	if prm.BearerToken != nil {
		callOpt = pool.WithBearer(prm.BearerToken)
	} else {
		callOpt = pool.WithKey(prm.PrivateKey)
	}

	idObj, err := x.pool.PutObject(ctx, *raw.Object(), prm.Payload, callOpt)
	if err != nil {
		return nil, fmt.Errorf("save object via connection pool: %w", err)
	}

	return idObj, nil
}

// SelectObjects selects user objects which match specified filters from the NeoFS container
// using connection pool.
//
// Returns any error encountered which prevented the selection to be finished.
// Returns layer.ErrAccessDenied on access violation.
func (x *NeoFS) SelectObjects(ctx context.Context, prm layer.PrmObjectSelect) ([]oid.ID, error) {
	var filters object.SearchFilters
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
			return nil, layer.ErrAccessDenied
		}

		return nil, fmt.Errorf("read object list: %w", err)
	}

	return buf, nil
}

// wraps io.ReadCloser and transforms Read errors related to access violation
// to layer.ErrAccessDenied.
type payloadReader struct {
	io.ReadCloser
}

func (x payloadReader) Read(p []byte) (int, error) {
	n, err := x.ReadCloser.Read(p)
	if err != nil {
		// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
		if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
			return n, layer.ErrAccessDenied
		}
	}

	return n, err
}

// ReadObject reads object part from the NeoFS container by identifier using connection pool:
//   * if with header only, then HeadObject is called;
//   * if with non-zero payload range only, then ObjectRange is called;
//   * else GetObject is called.
//
// Returns any error encountered which prevented the object to be read.
// Returns layer.ErrAccessDenied on access violation.
func (x *NeoFS) ReadObject(ctx context.Context, prm layer.PrmObjectRead) (*layer.ObjectPart, error) {
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
					return nil, layer.ErrAccessDenied
				}

				return nil, fmt.Errorf("init full object reading via connection pool: %w", err)
			}

			defer res.Payload.Close()

			payload, err := io.ReadAll(res.Payload)
			if err != nil {
				return nil, fmt.Errorf("read full object payload: %w", err)
			}

			object.NewRawFrom(&res.Header).SetPayload(payload)

			return &layer.ObjectPart{
				Head: &res.Header,
			}, nil
		}

		hdr, err := x.pool.HeadObject(ctx, addr, callOpt)
		if err != nil {
			// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
			if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
				return nil, layer.ErrAccessDenied
			}

			return nil, fmt.Errorf("read object header via connection pool: %w", err)
		}

		return &layer.ObjectPart{
			Head: hdr,
		}, nil
	} else if prm.PayloadRange[0]+prm.PayloadRange[1] == 0 {
		res, err := x.pool.GetObject(ctx, addr, callOpt)
		if err != nil {
			// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
			if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
				return nil, layer.ErrAccessDenied
			}

			return nil, fmt.Errorf("init full payload range reading via connection pool: %w", err)
		}

		return &layer.ObjectPart{
			Payload: res.Payload,
		}, nil
	}

	res, err := x.pool.ObjectRange(ctx, addr, prm.PayloadRange[0], prm.PayloadRange[1], callOpt)
	if err != nil {
		// TODO: (neofs-s3-gw#367) use NeoFS SDK API to check the status return
		if strings.Contains(err.Error(), "access to operation") && strings.Contains(err.Error(), "is denied by") {
			return nil, layer.ErrAccessDenied
		}

		return nil, fmt.Errorf("init payload range reading via connection pool: %w", err)
	}

	return &layer.ObjectPart{
		Payload: payloadReader{res},
	}, nil
}

// DeleteObject marks the object to be removed from the NeoFS container by identifier.
// Successful return does not guarantee the actual removal.
//
// Returns ErrAccessDenied on remove access violation.
//
// Returns any error encountered which prevented the removal request to be sent.
func (x *NeoFS) DeleteObject(ctx context.Context, prm layer.PrmObjectDelete) error {
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
			return layer.ErrAccessDenied
		}

		return fmt.Errorf("mark object removal via connection pool: %w", err)
	}

	return nil
}

// AuthmateNeoFS is a mediator which implements authmate.NeoFS through NeoFS.
type AuthmateNeoFS struct {
	*NeoFS
}

func (x *AuthmateNeoFS) CreateContainer(ctx context.Context, prm authmate.PrmContainerCreate) (*cid.ID, error) {
	return x.NeoFS.CreateContainer(ctx, PrmContainerCreate{
		Creator:  prm.Owner,
		Policy:   prm.Policy,
		Name:     prm.FriendlyName,
		Time:     time.Now(),
		BasicACL: 0b0011_1100_1000_1100_1000_1100_1100_1110, // 0x3C8C8CCE
	})
}

func (x *AuthmateNeoFS) ReadObjectPayload(ctx context.Context, addr address.Address) ([]byte, error) {
	res, err := x.NeoFS.ReadObject(ctx, layer.PrmObjectRead{
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

func (x *AuthmateNeoFS) CreateObject(ctx context.Context, prm tokens.PrmObjectCreate) (*oid.ID, error) {
	return x.NeoFS.CreateObject(ctx, PrmObjectCreate{
		Creator:         prm.Creator,
		Container:       prm.Container,
		Time:            prm.Time,
		Filename:        prm.Filename,
		ExpirationEpoch: prm.ExpirationEpoch,
		Payload:         bytes.NewReader(prm.Payload),
	})
}

// SystemDNS reads "SystemDNS" network parameter of the NeoFS.
//
// Returns exactly on non-zero value. Returns any error encountered
// which prevented the parameter to be read.
func (x *NeoFS) SystemDNS(ctx context.Context) (string, error) {
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
