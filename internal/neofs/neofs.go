package neofs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/object/slicer"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
	"github.com/nspcc-dev/tzhash/tz"
)

// Config allows to configure some [NeoFS] parameters.
type Config struct {
	MaxObjectSize           int64
	IsSlicerEnabled         bool
	IsHomomorphicEnabled    bool
	ContainerMetadataPolicy string
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

const (
	objectNonceSize = 8

	containerMetaDataPolicyAttribute  = "__NEOFS__METAINFO_CONSISTENCY"
	ContainerMetaDataPolicyStrict     = "strict"
	ContainerMetaDataPolicyOptimistic = "optimistic"
)

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
	cnr.SetPlacementPolicy(prm.Policy.Placement)
	cnr.SetOwner(prm.Creator)
	cnr.SetBasicACL(prm.BasicACL)

	creationTime := prm.CreationTime
	if creationTime.IsZero() {
		creationTime = time.Now()
	}
	cnr.SetCreationTime(creationTime)

	if !x.IsHomomorphicHashingEnabled() {
		cnr.DisableHomomorphicHashing()
	}

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

	if prm.Policy.Consistency == ContainerMetaDataPolicyStrict ||
		prm.Policy.Consistency == ContainerMetaDataPolicyOptimistic {
		cnr.SetAttribute(containerMetaDataPolicyAttribute, prm.Policy.Consistency)
	}

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

func (x *NeoFS) signMultipartObject(obj *object.Object, signer neofscrypto.Signer, payloadHash, homoHash hash.Hash) error {
	obj.SetPayloadChecksum(checksum.NewFromHash(checksum.SHA256, payloadHash))
	if homoHash != nil {
		obj.SetPayloadHomomorphicHash(checksum.NewFromHash(checksum.TillichZemor, homoHash))
	}

	if err := obj.SetIDWithSignature(signer); err != nil {
		return fmt.Errorf("set id with signature: %w", err)
	}

	return nil
}

// CreateObject implements neofs.NeoFS interface method.
func (x *NeoFS) CreateObject(ctx context.Context, prm layer.PrmObjectCreate) (oid.ID, error) {
	creationTime := prm.CreationTime
	if creationTime.IsZero() {
		creationTime = time.Now()
	}

	nonce := make([]byte, objectNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return oid.ID{}, fmt.Errorf("object nonce: %w", err)
	}

	uniqAttributes := maps.Clone(prm.Attributes)
	if uniqAttributes == nil {
		uniqAttributes = make(map[string]string)
	}

	uniqAttributes[object.AttributeTimestamp] = strconv.FormatInt(creationTime.Unix(), 10)
	uniqAttributes[s3headers.AttributeObjectNonce] = base64.StdEncoding.EncodeToString(nonce)

	if prm.Filepath != "" {
		uniqAttributes[object.AttributeFilePath] = prm.Filepath
	}

	attrs := make([]object.Attribute, 0, len(uniqAttributes))
	for k, v := range uniqAttributes {
		attr := object.NewAttribute(k, v)
		attrs = append(attrs, attr)
	}

	var obj object.Object
	obj.SetContainerID(prm.Container)
	obj.SetOwner(prm.Creator)
	obj.SetAttributes(attrs...)
	obj.SetPayloadSize(prm.PayloadSize)

	if prm.Multipart != nil {
		obj.SetOwner(x.signer(ctx).UserID())

		if prm.Multipart.SplitPreviousID != nil {
			obj.SetPreviousID(*prm.Multipart.SplitPreviousID)
		}

		if prm.Multipart.SplitFirstID != nil {
			obj.SetFirstID(*prm.Multipart.SplitFirstID)
		}

		if prm.Multipart.HeaderObject != nil {
			obj.SetParent(prm.Multipart.HeaderObject)

			if id := prm.Multipart.HeaderObject.GetID(); !id.IsZero() {
				obj.SetParentID(id)
			}
		}

		if prm.Multipart.Link != nil {
			obj.WriteLink(*prm.Multipart.Link)
			prm.Payload = bytes.NewReader(obj.Payload())
			obj.SetPayloadSize(uint64(len(obj.Payload())))

			prm.Multipart.PayloadHash = sha256.New()
			prm.Multipart.PayloadHash.Write(obj.Payload())

			if x.IsHomomorphicHashingEnabled() {
				prm.Multipart.HomoHash = tz.New()
				prm.Multipart.HomoHash.Write(obj.Payload())
			}

			// Link object should never have a previous one.
			obj.ResetPreviousID()
		}

		if err := x.signMultipartObject(
			&obj,
			x.signer(ctx),
			prm.Multipart.PayloadHash,
			prm.Multipart.HomoHash,
		); err != nil {
			return oid.ID{}, errors.New("failed to sign object")
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
		var signer = x.signer(ctx)

		obj.SetOwner(signer.UserID())

		opts := slicer.Options{}
		opts.SetObjectPayloadLimit(uint64(x.cfg.MaxObjectSize))
		opts.SetCopiesNumber(prm.CopiesNumber)
		opts.SetCurrentNeoFSEpoch(x.epochGetter.CurrentEpoch())
		opts.SetPayloadSize(prm.PayloadSize)

		var (
			chunk        *[]byte
			returnToPool bool
		)

		if prm.PayloadSize > 0 && prm.PayloadSize < uint64(x.MaxObjectSize()/2) {
			c := make([]byte, prm.PayloadSize)
			chunk = &c
		} else {
			data := x.buffers.Get()
			chunk = data.(*[]byte)
			returnToPool = true
		}

		opts.SetPayloadBuffer(*chunk)

		if x.cfg.IsHomomorphicEnabled {
			opts.CalculateHomomorphicChecksum()
		}

		if prm.BearerToken != nil {
			opts.SetBearerToken(*prm.BearerToken)
		}

		objID, err := slicer.Put(ctx, x.pool, obj, signer, prm.Payload, opts)
		if returnToPool {
			x.buffers.Put(chunk)
		}

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
		return oid.ID{}, fmt.Errorf("put init: %w", err)
	}

	var (
		chunk        *[]byte
		returnToPool bool
	)

	if prm.PayloadSize > 0 && prm.PayloadSize < uint64(x.MaxObjectSize()/2) {
		c := make([]byte, prm.PayloadSize)
		chunk = &c
	} else {
		data := x.buffers.Get()
		chunk = data.(*[]byte)
		returnToPool = true
	}

	_, err = io.CopyBuffer(writer, prm.Payload, *chunk)
	if returnToPool {
		x.buffers.Put(chunk)
	}

	if err != nil {
		return oid.ID{}, fmt.Errorf("copy payload with buffer: %w", err)
	}

	if err = writer.Close(); err != nil {
		return oid.ID{}, fmt.Errorf("writer close: %w", err)
	}

	return writer.GetResult().StoredObjectID(), nil
}

// FinalizeObjectWithPayloadChecksums implements neofs.NeoFS interface method.
func (x *NeoFS) FinalizeObjectWithPayloadChecksums(ctx context.Context, header object.Object, metaChecksum hash.Hash, homomorphicChecksum hash.Hash, payloadLength uint64) (*object.Object, error) {
	header.SetOwner(x.signer(ctx).UserID())
	header.SetCreationEpoch(x.epochGetter.CurrentEpoch())

	header.SetPayloadChecksum(checksum.NewFromHash(checksum.SHA256, metaChecksum))

	if homomorphicChecksum != nil {
		header.SetPayloadHomomorphicHash(checksum.NewFromHash(checksum.TillichZemor, homomorphicChecksum))
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

// GetObject implements neofs.NeoFS interface method.
func (x *NeoFS) GetObject(ctx context.Context, prm layer.GetObject) (*layer.ObjectPart, error) {
	var (
		prmGet client.PrmObjectGet
	)

	if prm.BearerToken != nil {
		prmGet.WithBearerToken(*prm.BearerToken)
	}

	header, res, err := x.pool.ObjectGetInit(ctx, prm.Container, prm.Object, x.signer(ctx), prmGet)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}

		return nil, fmt.Errorf("init full object reading via connection pool: %w", err)
	}

	return &layer.ObjectPart{
		Head:    &header,
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

// CurrentEpoch returns current epoch.
func (x *NeoFS) CurrentEpoch() uint64 {
	return x.epochGetter.CurrentEpoch()
}

func isErrAccessDenied(err error) (string, bool) {
	var (
		oad  apistatus.ObjectAccessDenied
		oadp *apistatus.ObjectAccessDenied
	)
	switch {
	case errors.As(err, &oad):
		return oad.Reason(), true
	case errors.As(err, &oadp):
		return oadp.Reason(), true
	default:
		return "", false
	}
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
		Policy:        layer.PlacementPolicy{Placement: prm.Policy, Version: layer.PlacementPolicyV1},
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
		Creator:    prm.Creator,
		Container:  prm.Container,
		Filepath:   prm.Filepath,
		Attributes: map[string]string{object.AttributeExpirationEpoch: strconv.FormatUint(prm.ExpirationEpoch, 10)},
		Payload:    bytes.NewReader(prm.Payload),
	})
}

// SetContainerEACL implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) SetContainerEACL(ctx context.Context, table eacl.Table, sessionToken *session.Container) error {
	return x.neoFS.SetContainerEACL(ctx, table, sessionToken)
}

// ContainerEACL implements authmate.NeoFS interface method.
func (x *AuthmateNeoFS) ContainerEACL(ctx context.Context, containerID cid.ID) (*eacl.Table, error) {
	return x.neoFS.ContainerEACL(ctx, containerID)
}

// SearchObjects implements neofs.NeoFS interface method.
func (x *NeoFS) SearchObjects(ctx context.Context, prm layer.PrmObjectSearch) ([]oid.ID, error) {
	var prmSearch client.PrmObjectSearch
	if prm.BearerToken != nil {
		prmSearch.WithBearerToken(*prm.BearerToken)
	}

	prmSearch.SetFilters(prm.Filters)
	prmSearch.WithXHeaders(prm.XHeaders...)

	rdr, err := x.pool.ObjectSearchInit(ctx, prm.Container, x.signer(ctx), prmSearch)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			return nil, fmt.Errorf("%w: %s", layer.ErrAccessDenied, reason)
		}

		return nil, fmt.Errorf("init object search via connection pool: %w", err)
	}

	defer func() {
		_ = rdr.Close()
	}()

	var oids []oid.ID

	iteratorFunc := func(id oid.ID) bool {
		oids = append(oids, id)
		return false
	}

	if err = rdr.Iterate(iteratorFunc); err != nil {
		return nil, fmt.Errorf("iterate object search via connection pool: %w", err)
	}

	return oids, nil
}

// SearchObjectsV2 implements neofs.NeoFS interface method.
func (x *NeoFS) SearchObjectsV2(ctx context.Context, cid cid.ID, filters object.SearchFilters, attributes []string, opts client.SearchObjectsOptions) ([]client.SearchResultItem, error) {
	var (
		resultItems []client.SearchResultItem
		items       []client.SearchResultItem
		cursor      string
		err         error
	)

	for {
		items, cursor, err = x.SearchObjectsV2WithCursor(ctx, cid, filters, attributes, cursor, opts)
		if err != nil {
			return nil, fmt.Errorf("search objects with cursor: %w", err)
		}

		resultItems = append(resultItems, items...)

		if cursor == "" {
			break
		}
	}

	return resultItems, nil
}

// SearchObjectsV2WithCursor implements neofs.NeoFS interface method.
func (x *NeoFS) SearchObjectsV2WithCursor(ctx context.Context, cid cid.ID, filters object.SearchFilters, attributes []string, cursor string, opts client.SearchObjectsOptions) ([]client.SearchResultItem, string, error) {
	items, cursor, err := x.pool.SearchObjects(ctx, cid, filters, attributes, cursor, x.signer(ctx), opts)
	if err != nil {
		return nil, "", fmt.Errorf("search objects: %w", err)
	}

	return items, cursor, nil
}
