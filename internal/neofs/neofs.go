package neofs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/object/slicer"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/stat"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
	"github.com/nspcc-dev/tzhash/tz"
)

// Config allows to configure some [NeoFS] parameters.
type Config struct {
	MaxObjectSize        int64
	IsSlicerEnabled      bool
	IsHomomorphicEnabled bool
}

// NeoFS represents virtual connection to the NeoFS network.
// It is used to provide an interface to dependent packages
// which work with NeoFS.
type NeoFS struct {
	pool        *pool.Pool
	gateSigner  user.Signer
	anonSigner  user.Signer
	cfg         Config
	epochGetter EpochGetter
	buffers     *sync.Pool
}

// NewNeoFS creates new NeoFS using provided pool.Pool.
func NewNeoFS(p *pool.Pool, signer user.Signer, anonSigner user.Signer, cfg Config, epochGetter EpochGetter) *NeoFS {
	buffers := sync.Pool{}
	buffers.New = func() any {
		b := make([]byte, cfg.MaxObjectSize)
		return &b
	}

	return &NeoFS{
		pool:        p,
		gateSigner:  signer,
		anonSigner:  anonSigner,
		cfg:         cfg,
		epochGetter: epochGetter,
		buffers:     &buffers,
	}
}

func (x *NeoFS) signer(ctx context.Context) user.Signer {
	if api.IsAnonymousRequest(ctx) {
		return x.anonSigner
	}

	return x.gateSigner
}

// TimeToEpoch implements neofs.NeoFS interface method.
func (x *NeoFS) TimeToEpoch(ctx context.Context, now, futureTime time.Time) (uint64, uint64, error) {
	dur := futureTime.Sub(now)
	if dur < 0 {
		return 0, 0, fmt.Errorf("time '%s' must be in the future (after %s)",
			futureTime.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	networkInfo, err := x.pool.NetworkInfo(ctx, client.PrmNetworkInfo{})
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
	var prm client.PrmContainerGet
	res, err := x.pool.ContainerGet(ctx, idCnr, prm)
	if err != nil {
		return nil, fmt.Errorf("read container via connection pool: %w", err)
	}

	return &res, nil
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

	creationTime := prm.CreationTime
	if creationTime.IsZero() {
		creationTime = time.Now()
	}
	cnr.SetCreationTime(creationTime)

	if prm.Name != "" {
		var d container.Domain
		d.SetName(prm.Name)

		cnr.WriteDomain(d)
		cnr.SetName(prm.Name)
	}

	for i := range prm.AdditionalAttributes {
		cnr.SetAttribute(prm.AdditionalAttributes[i][0], prm.AdditionalAttributes[i][1])
	}

	cnr.SetAttribute(layer.AttributeOwnerPublicKey, hex.EncodeToString(prm.CreatorPubKey.Bytes()))

	err := client.SyncContainerWithNetwork(ctx, &cnr, x.pool)
	if err != nil {
		return cid.ID{}, fmt.Errorf("sync container with the network state: %w", err)
	}

	var prmPut client.PrmContainerPut
	if prm.SessionToken != nil {
		prmPut.WithinSession(*prm.SessionToken)
	}

	putWaiter := waiter.NewContainerPutWaiter(x.pool, waiter.DefaultPollInterval)

	// send request to save the container
	idCnr, err := putWaiter.ContainerPut(ctx, cnr, x.signer(ctx), prmPut)
	if err != nil {
		return cid.ID{}, fmt.Errorf("save container via connection pool: %w", err)
	}

	return idCnr, nil
}

// UserContainers implements neofs.NeoFS interface method.
func (x *NeoFS) UserContainers(ctx context.Context, id user.ID) ([]cid.ID, error) {
	var prm client.PrmContainerList
	r, err := x.pool.ContainerList(ctx, id, prm)
	if err != nil {
		return nil, fmt.Errorf("list user containers via connection pool: %w", err)
	}

	return r, nil
}

// SetContainerEACL implements neofs.NeoFS interface method.
func (x *NeoFS) SetContainerEACL(ctx context.Context, table eacl.Table, sessionToken *session.Container) error {
	var prm client.PrmContainerSetEACL
	if sessionToken != nil {
		prm.WithinSession(*sessionToken)
	}

	eaclWaiter := waiter.NewContainerSetEACLWaiter(x.pool, waiter.DefaultPollInterval)
	err := eaclWaiter.ContainerSetEACL(ctx, table, x.signer(ctx), prm)
	if err != nil {
		return fmt.Errorf("save eACL via connection pool: %w", err)
	}

	return err
}

// ContainerEACL implements neofs.NeoFS interface method.
func (x *NeoFS) ContainerEACL(ctx context.Context, id cid.ID) (*eacl.Table, error) {
	var prm client.PrmContainerEACL
	res, err := x.pool.ContainerEACL(ctx, id, prm)
	if err != nil {
		return nil, fmt.Errorf("read eACL via connection pool: %w", err)
	}

	return &res, nil
}

// DeleteContainer implements neofs.NeoFS interface method.
func (x *NeoFS) DeleteContainer(ctx context.Context, id cid.ID, token *session.Container) error {
	var prm client.PrmContainerDelete
	if token != nil {
		prm.WithinSession(*token)
	}

	deleteWaiter := waiter.NewContainerDeleteWaiter(x.pool, waiter.DefaultPollInterval)
	err := deleteWaiter.ContainerDelete(ctx, id, x.signer(ctx), prm)
	if err != nil {
		return fmt.Errorf("delete container via connection pool: %w", err)
	}

	return nil
}

// CreateObject implements neofs.NeoFS interface method.
func (x *NeoFS) CreateObject(ctx context.Context, prm layer.PrmObjectCreate) (oid.ID, error) {
	attrNum := len(prm.Attributes) + 1 // + creation time

	if prm.Filepath != "" {
		attrNum++
	}

	attrs := make([]object.Attribute, 0, attrNum)

	creationTime := prm.CreationTime
	if creationTime.IsZero() {
		creationTime = time.Now()
	}
	var a *object.Attribute
	a = object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(creationTime.Unix(), 10))

	attrs = append(attrs, *a)

	for i := range prm.Attributes {
		a = object.NewAttribute(prm.Attributes[i][0], prm.Attributes[i][1])
		attrs = append(attrs, *a)
	}

	if prm.Filepath != "" {
		a = object.NewAttribute(object.AttributeFilePath, prm.Filepath)
		attrs = append(attrs, *a)
	}

	var obj object.Object
	obj.SetContainerID(prm.Container)
	obj.SetOwnerID(&prm.Creator)
	obj.SetAttributes(attrs...)
	obj.SetPayloadSize(prm.PayloadSize)

	if prm.Multipart != nil && prm.Multipart.SplitID != "" {
		var split object.SplitID
		if err := split.Parse(prm.Multipart.SplitID); err != nil {
			return oid.ID{}, fmt.Errorf("parse split ID: %w", err)
		}
		obj.SetSplitID(&split)

		if prm.Multipart.SplitPreviousID != nil {
			obj.SetPreviousID(*prm.Multipart.SplitPreviousID)
		}

		if len(prm.Multipart.Children) > 0 {
			obj.SetChildren(prm.Multipart.Children...)
		}

		if prm.Multipart.HeaderObject != nil {
			id, isSet := prm.Multipart.HeaderObject.ID()
			if !isSet {
				return oid.ID{}, errors.New("HeaderObject id is not set")
			}

			obj.SetParentID(id)
			obj.SetParent(prm.Multipart.HeaderObject)
		}
	}

	if len(prm.Locks) > 0 {
		var lock object.Lock
		lock.WriteMembers(prm.Locks)
		obj.WriteLock(lock)

		// we can't have locks and payload at the same time.
		if len(obj.Payload()) > 0 && prm.Payload != nil {
			return oid.ID{}, errors.New("lock object with payload")
		}

		prm.Payload = bytes.NewReader(obj.Payload())
	}

	if x.cfg.IsSlicerEnabled {
		opts := slicer.Options{}
		opts.SetObjectPayloadLimit(uint64(x.cfg.MaxObjectSize))
		opts.SetCopiesNumber(prm.CopiesNumber)
		opts.SetCurrentNeoFSEpoch(x.epochGetter.CurrentEpoch())
		opts.SetPayloadSize(prm.PayloadSize)

		data := x.buffers.Get()
		chunk := data.(*[]byte)
		opts.SetPayloadBuffer(*chunk)

		if x.cfg.IsHomomorphicEnabled {
			opts.CalculateHomomorphicChecksum()
		}

		if prm.BearerToken != nil {
			opts.SetBearerToken(*prm.BearerToken)
		}

		objID, err := slicer.Put(ctx, x.pool, obj, x.signer(ctx), prm.Payload, opts)
		x.buffers.Put(chunk)

		if err != nil {
			return oid.ID{}, fmt.Errorf("slicer put: %w", err)
		}

		return objID, nil
	}

	var prmObjPutInit client.PrmObjectPutInit
	prmObjPutInit.SetCopiesNumber(prm.CopiesNumber)

	if prm.BearerToken != nil {
		prmObjPutInit.WithBearerToken(*prm.BearerToken)
	}

	writer, err := x.pool.ObjectPutInit(ctx, obj, x.signer(ctx), prmObjPutInit)
	if err != nil {
		reason, ok := isErrAccessDenied(err)
		if ok {
			return oid.ID{}, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}
		return oid.ID{}, fmt.Errorf("save object via connection pool: %w", err)
	}

	data := x.buffers.Get()
	chunk := data.(*[]byte)

	_, err = io.CopyBuffer(writer, prm.Payload, *chunk)
	x.buffers.Put(chunk)

	if err != nil {
		return oid.ID{}, fmt.Errorf("read payload chunk: %w", err)
	}

	if err = writer.Close(); err != nil {
		return oid.ID{}, fmt.Errorf("writer close: %w", err)
	}

	return writer.GetResult().StoredObjectID(), nil
}

// FinalizeObjectWithPayloadChecksums implements neofs.NeoFS interface method.
func (x *NeoFS) FinalizeObjectWithPayloadChecksums(ctx context.Context, header object.Object, metaChecksum hash.Hash, homomorphicChecksum hash.Hash, payloadLength uint64) (*object.Object, error) {
	header.SetCreationEpoch(x.epochGetter.CurrentEpoch())

	var cs checksum.Checksum

	var csBytes [sha256.Size]byte
	copy(csBytes[:], metaChecksum.Sum(nil))

	cs.SetSHA256(csBytes)
	header.SetPayloadChecksum(cs)

	if homomorphicChecksum != nil {
		var csHomoBytes [tz.Size]byte
		copy(csHomoBytes[:], homomorphicChecksum.Sum(nil))

		cs.SetTillichZemor(csHomoBytes)
		header.SetPayloadHomomorphicHash(cs)
	}

	header.SetPayloadSize(payloadLength)
	if err := header.SetIDWithSignature(x.signer(ctx)); err != nil {
		return nil, fmt.Errorf("setIDWithSignature: %w", err)
	}

	return &header, nil
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
	var prmGet client.PrmObjectGet

	if prm.BearerToken != nil {
		prmGet.WithBearerToken(*prm.BearerToken)
	}

	if prm.WithHeader {
		if prm.WithPayload {
			header, res, err := x.pool.ObjectGetInit(ctx, prm.Container, prm.Object, x.signer(ctx), prmGet)
			if err != nil {
				if reason, ok := isErrAccessDenied(err); ok {
					return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
				}

				return nil, fmt.Errorf("init full object reading via connection pool: %w", err)
			}

			defer res.Close()

			payload, err := io.ReadAll(res)
			if err != nil {
				return nil, fmt.Errorf("read full object payload: %w", err)
			}

			header.SetPayload(payload)

			return &layer.ObjectPart{
				Head: &header,
			}, nil
		}

		var prmHead client.PrmObjectHead

		if prm.BearerToken != nil {
			prmHead.WithBearerToken(*prm.BearerToken)
		}

		hdr, err := x.pool.ObjectHead(ctx, prm.Container, prm.Object, x.signer(ctx), prmHead)
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
		_, res, err := x.pool.ObjectGetInit(ctx, prm.Container, prm.Object, x.signer(ctx), prmGet)
		if err != nil {
			if reason, ok := isErrAccessDenied(err); ok {
				return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
			}

			return nil, fmt.Errorf("init full payload range reading via connection pool: %w", err)
		}

		return &layer.ObjectPart{
			Payload: res,
		}, nil
	}

	var prmRange client.PrmObjectRange

	if prm.BearerToken != nil {
		prmRange.WithBearerToken(*prm.BearerToken)
	}

	res, err := x.pool.ObjectRangeInit(ctx, prm.Container, prm.Object, prm.PayloadRange[0], prm.PayloadRange[1], x.signer(ctx), prmRange)
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
	var prmDelete client.PrmObjectDelete

	if prm.BearerToken != nil {
		prmDelete.WithBearerToken(*prm.BearerToken)
	}

	_, err := x.pool.ObjectDelete(ctx, prm.Container, prm.Object, x.signer(ctx), prmDelete)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}

		return fmt.Errorf("mark object removal via connection pool: %w", err)
	}

	return nil
}

// MaxObjectSize returns configured payload size limit for object slicing when enabled.
func (x *NeoFS) MaxObjectSize() int64 {
	return x.cfg.MaxObjectSize
}

// IsHomomorphicHashingEnabled shows if homomorphic hashing is enabled in config.
func (x *NeoFS) IsHomomorphicHashingEnabled() bool {
	return x.cfg.IsHomomorphicEnabled
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
	networkInfo, err := x.pool.NetworkInfo(ctx, client.PrmNetworkInfo{})
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
	neoFS layer.NeoFS
}

// NewAuthmateNeoFS creates new AuthmateNeoFS using provided pool.Pool.
func NewAuthmateNeoFS(neoFS layer.NeoFS) *AuthmateNeoFS {
	return &AuthmateNeoFS{neoFS: neoFS}
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
	return x.neoFS.TimeToEpoch(ctx, time.Now(), futureTime)
}

// CreateContainer implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) CreateContainer(ctx context.Context, prm authmate.PrmContainerCreate) (cid.ID, error) {
	basicACL := acl.Private
	// allow reading objects to OTHERS in order to provide read access to S3 gateways
	basicACL.AllowOp(acl.OpObjectGet, acl.RoleOthers)

	return x.neoFS.CreateContainer(ctx, layer.PrmContainerCreate{
		Creator:       prm.Owner,
		Policy:        prm.Policy,
		Name:          prm.FriendlyName,
		BasicACL:      basicACL,
		CreatorPubKey: prm.CreatorPubKey,
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
		Filepath:  prm.Filepath,
		Attributes: [][2]string{
			{object.AttributeExpirationEpoch, strconv.FormatUint(prm.ExpirationEpoch, 10)}},
		Payload: bytes.NewReader(prm.Payload),
	})
}

// PoolStatistic is a mediator which implements authmate.NeoFS through pool.Pool.
type PoolStatistic struct {
	poolStat *stat.PoolStat
}

// NewPoolStatistic creates new PoolStatistic using provided pool.Pool.
func NewPoolStatistic(poolStat *stat.PoolStat) *PoolStatistic {
	return &PoolStatistic{poolStat: poolStat}
}

// Statistic implements interface method.
func (x *PoolStatistic) Statistic() stat.Statistic {
	return x.poolStat.Statistic()
}
