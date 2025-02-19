package layer

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
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/tzhash/tz"
)

type TestNeoFS struct {
	NeoFS

	objects      map[string]*object.Object
	containers   map[string]*container.Container
	eaclTables   map[string]*eacl.Table
	currentEpoch uint64
	signer       neofscrypto.Signer
}

const (
	objectNonceSize      = 8
	objectNonceAttribute = "__NEOFS__NONCE"
)

func NewTestNeoFS(signer neofscrypto.Signer) *TestNeoFS {
	return &TestNeoFS{
		objects:    make(map[string]*object.Object),
		containers: make(map[string]*container.Container),
		eaclTables: make(map[string]*eacl.Table),
		signer:     signer,
	}
}

func (t *TestNeoFS) CurrentEpoch() uint64 {
	return t.currentEpoch
}

func (t *TestNeoFS) Objects() []*object.Object {
	res := make([]*object.Object, 0, len(t.objects))

	for _, obj := range t.objects {
		res = append(res, obj)
	}

	return res
}

func (t *TestNeoFS) AddObject(key string, obj *object.Object) {
	t.objects[key] = obj
}

func (t *TestNeoFS) ContainerID(name string) (cid.ID, error) {
	for id, cnr := range t.containers {
		if cnr.Name() == name {
			var cnrID cid.ID
			return cnrID, cnrID.DecodeString(id)
		}
	}
	return cid.ID{}, fmt.Errorf("not found")
}

func (t *TestNeoFS) CreateContainer(_ context.Context, prm PrmContainerCreate) (cid.ID, error) {
	var cnr container.Container
	cnr.Init()
	cnr.SetOwner(prm.Creator)
	cnr.SetPlacementPolicy(prm.Policy)
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

	cnr.SetAttribute(AttributeOwnerPublicKey, hex.EncodeToString(prm.CreatorPubKey.Bytes()))

	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return cid.ID{}, err
	}

	var id cid.ID
	id.SetSHA256(sha256.Sum256(b))
	t.containers[id.EncodeToString()] = &cnr

	return id, nil
}

func (t *TestNeoFS) DeleteContainer(_ context.Context, cnrID cid.ID, _ *session.Container) error {
	delete(t.containers, cnrID.EncodeToString())

	return nil
}

func (t *TestNeoFS) Container(_ context.Context, id cid.ID) (*container.Container, error) {
	for k, v := range t.containers {
		if k == id.EncodeToString() {
			return v, nil
		}
	}

	return nil, fmt.Errorf("container not found %s", id)
}

func (t *TestNeoFS) UserContainers(_ context.Context, _ user.ID) ([]cid.ID, error) {
	var res []cid.ID
	for k := range t.containers {
		var idCnr cid.ID
		if err := idCnr.DecodeString(k); err != nil {
			return nil, err
		}
		res = append(res, idCnr)
	}

	return res, nil
}

func (t *TestNeoFS) ReadObject(ctx context.Context, prm PrmObjectRead) (*ObjectPart, error) {
	var addr oid.Address
	addr.SetContainer(prm.Container)
	addr.SetObject(prm.Object)

	sAddr := addr.EncodeToString()

	obj, ok := t.objects[sAddr]
	if !ok {
		// trying to find linking object.
		for _, o := range t.objects {
			parentID, isSet := o.ParentID()
			if !isSet {
				continue
			}

			if !parentID.Equals(prm.Object) {
				continue
			}

			if len(o.Children()) == 0 {
				continue
			}

			// linking object is found.
			objPart, err := t.constructMupltipartObject(ctx, prm.Container, o)
			if err != nil {
				return nil, err
			}

			obj = objPart.Head

			pl, err := io.ReadAll(objPart.Payload)
			if err != nil {
				return nil, err
			}

			obj.SetPayload(pl)
			ok = true
			break
		}
	}

	if !ok {
		return nil, fmt.Errorf("object not found %s", addr)
	}

	owner := getOwner(ctx)
	if !obj.OwnerID().Equals(owner) {
		return nil, ErrAccessDenied
	}

	payload := obj.Payload()

	if prm.PayloadRange[0]+prm.PayloadRange[1] > 0 {
		off := prm.PayloadRange[0]
		payload = payload[off : off+prm.PayloadRange[1]]
	}

	return &ObjectPart{
		Head:    obj,
		Payload: io.NopCloser(bytes.NewReader(payload)),
	}, nil
}

func (t *TestNeoFS) constructMupltipartObject(ctx context.Context, containerID cid.ID, linkingObject *object.Object) (*ObjectPart, error) {
	if _, isSet := linkingObject.ParentID(); !isSet {
		return nil, fmt.Errorf("linking object is invalid")
	}

	var (
		addr           oid.Address
		headObject     = linkingObject.Parent()
		payloadReaders = make([]io.Reader, 0, len(linkingObject.Children()))
		childList      = linkingObject.Children()
	)

	addr.SetContainer(containerID)

	for _, c := range childList {
		addr.SetObject(c)

		objPart, err := t.ReadObject(ctx, PrmObjectRead{
			Container: containerID,
			Object:    c,
		})

		if err != nil {
			return nil, fmt.Errorf("child read: %w", err)
		}

		payloadReaders = append(payloadReaders, objPart.Payload)
	}

	return &ObjectPart{
		Head:    headObject,
		Payload: io.NopCloser(io.MultiReader(payloadReaders...)),
	}, nil
}

func (t *TestNeoFS) CreateObject(_ context.Context, prm PrmObjectCreate) (oid.ID, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return oid.ID{}, err
	}
	var id oid.ID
	id.SetSHA256(sha256.Sum256(b))

	attrs := make([]object.Attribute, 0)
	creationTime := prm.CreationTime
	if creationTime.IsZero() {
		creationTime = time.Now()
	}

	var a *object.Attribute
	a = object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(creationTime.Unix(), 10))
	attrs = append(attrs, *a)

	if prm.Filepath != "" {
		a = object.NewAttribute(object.AttributeFilePath, prm.Filepath)
		attrs = append(attrs, *a)
	}

	for k, v := range prm.Attributes {
		a = object.NewAttribute(k, v)
		attrs = append(attrs, *a)
	}

	nonce := make([]byte, objectNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return oid.ID{}, fmt.Errorf("object nonce: %w", err)
	}
	objectNonceAttr := object.NewAttribute(objectNonceAttribute, base64.StdEncoding.EncodeToString(nonce))
	attrs = append(attrs, *objectNonceAttr)

	obj := object.New()
	obj.SetContainerID(prm.Container)
	obj.SetID(id)
	obj.SetPayloadSize(prm.PayloadSize)
	obj.SetAttributes(attrs...)
	obj.SetCreationEpoch(t.currentEpoch)
	obj.SetOwnerID(&prm.Creator)
	t.currentEpoch++

	if prm.Multipart != nil {
		if prm.Multipart.SplitPreviousID != nil {
			obj.SetPreviousID(*prm.Multipart.SplitPreviousID)
		}

		if prm.Multipart.SplitFirstID != nil {
			obj.SetFirstID(*prm.Multipart.SplitFirstID)
		}

		if prm.Multipart.HeaderObject != nil {
			obj.SetParent(prm.Multipart.HeaderObject)

			if hid, isSet := prm.Multipart.HeaderObject.ID(); isSet {
				obj.SetParentID(hid)
			}
		}

		if prm.Multipart.Link != nil {
			obj.WriteLink(*prm.Multipart.Link)
			prm.Payload = bytes.NewReader(obj.Payload())
			obj.SetPayloadSize(uint64(len(obj.Payload())))

			var (
				addr    oid.Address
				payload []byte
			)

			for _, e := range prm.Multipart.Link.Objects() {
				addr = newAddress(prm.Container, e.ObjectID())
				if partialObject, ok := t.objects[addr.EncodeToString()]; ok {
					payload = append(payload, partialObject.Payload()...)
				}
			}

			pid, isSet := prm.Multipart.HeaderObject.ID()
			if !isSet {
				return oid.ID{}, errors.New("HeaderObject id is not set")
			}

			realHeaderObj := object.New()
			realHeaderObj.SetContainerID(prm.Container)
			realHeaderObj.SetID(pid)
			realHeaderObj.SetPayloadSize(uint64(len(payload)))
			realHeaderObj.SetAttributes(attrs...)
			realHeaderObj.SetCreationEpoch(t.currentEpoch)
			realHeaderObj.SetOwnerID(&prm.Creator)
			realHeaderObj.SetPayload(payload)

			var h checksum.Checksum
			checksum.Calculate(&h, checksum.SHA256, payload)
			realHeaderObj.SetPayloadChecksum(h)

			addr = newAddress(prm.Container, pid)
			t.objects[addr.EncodeToString()] = realHeaderObj
		}
	}

	if len(prm.Locks) > 0 {
		var lock object.Lock
		lock.WriteMembers(prm.Locks)
		obj.WriteLock(lock)
	}

	if prm.Payload != nil {
		all, err := io.ReadAll(prm.Payload)
		if err != nil {
			return oid.ID{}, err
		}
		obj.SetPayload(all)
		obj.SetPayloadSize(uint64(len(all)))
		var hash checksum.Checksum
		checksum.Calculate(&hash, checksum.SHA256, all)
		obj.SetPayloadChecksum(hash)
	}

	cnrID, _ := obj.ContainerID()
	objID, _ := obj.ID()

	addr := newAddress(cnrID, objID)
	t.objects[addr.EncodeToString()] = obj
	return objID, nil
}

func (t *TestNeoFS) FinalizeObjectWithPayloadChecksums(_ context.Context, header object.Object, metaChecksum hash.Hash, homomorphicChecksum hash.Hash, payloadLength uint64) (*object.Object, error) {
	header.SetCreationEpoch(t.currentEpoch)

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
	if err := header.SetIDWithSignature(t.signer); err != nil {
		return nil, fmt.Errorf("setIDWithSignature: %w", err)
	}
	return &header, nil
}

func (t *TestNeoFS) DeleteObject(ctx context.Context, prm PrmObjectDelete) error {
	var addr oid.Address
	addr.SetContainer(prm.Container)
	addr.SetObject(prm.Object)

	if obj, ok := t.objects[addr.EncodeToString()]; ok {
		owner := getOwner(ctx)
		if !obj.OwnerID().Equals(owner) {
			return ErrAccessDenied
		}

		delete(t.objects, addr.EncodeToString())
	}

	return nil
}

func (t *TestNeoFS) TimeToEpoch(_ context.Context, now, futureTime time.Time) (uint64, uint64, error) {
	return t.currentEpoch, t.currentEpoch + uint64(futureTime.Sub(now).Seconds()), nil
}

func (t *TestNeoFS) MaxObjectSize() int64 {
	// 64 MB
	return 67108864
}

func (t *TestNeoFS) IsHomomorphicHashingEnabled() bool {
	return false
}

func (t *TestNeoFS) AllObjects(cnrID cid.ID) []oid.ID {
	result := make([]oid.ID, 0, len(t.objects))

	for _, val := range t.objects {
		objCnrID, _ := val.ContainerID()
		objObjID, _ := val.ID()
		if cnrID.Equals(objCnrID) {
			result = append(result, objObjID)
		}
	}

	return result
}

func (t *TestNeoFS) SetContainerEACL(_ context.Context, table eacl.Table, _ *session.Container) error {
	cnrID, ok := table.CID()
	if !ok {
		return errors.New("invalid cid")
	}

	if _, ok = t.containers[cnrID.EncodeToString()]; !ok {
		return errors.New("not found")
	}

	t.eaclTables[cnrID.EncodeToString()] = &table

	return nil
}

func (t *TestNeoFS) ContainerEACL(_ context.Context, cnrID cid.ID) (*eacl.Table, error) {
	table, ok := t.eaclTables[cnrID.EncodeToString()]
	if !ok {
		return nil, errors.New("not found")
	}

	return table, nil
}

func getOwner(ctx context.Context) user.ID {
	if bd, ok := ctx.Value(api.BoxData).(*accessbox.Box); ok && bd != nil && bd.Gate != nil && bd.Gate.BearerToken != nil {
		return bd.Gate.BearerToken.ResolveIssuer()
	}

	return user.ID{}
}

// SearchObjects searches objects with corresponding filters.
func (t *TestNeoFS) SearchObjects(_ context.Context, prm PrmObjectSearch) ([]oid.ID, error) {
	var oids []oid.ID

	if len(prm.Filters) == 0 {
		for _, obj := range t.objects {
			oids = append(oids, obj.GetID())
		}

		return oids, nil
	}

	for _, obj := range t.objects {
		if checkFilters(obj, prm.Filters) {
			oids = append(oids, obj.GetID())
		}
	}

	return oids, nil
}

// SearchObjectsV2 implements neofs.NeoFS interface method.
func (t *TestNeoFS) SearchObjectsV2(_ context.Context, cid cid.ID, filters object.SearchFilters, attributes []string, _ client.SearchObjectsOptions) ([]client.SearchResultItem, error) {
	var oids []client.SearchResultItem

	if len(filters) == 0 {
		for _, obj := range t.objects {
			if obj.GetContainerID() != cid {
				continue
			}

			oids = append(oids, fillResultObject(obj, attributes))
		}

		return oids, nil
	}

	for _, obj := range t.objects {
		if obj.GetContainerID() != cid {
			continue
		}

		if checkFilters(obj, filters) {
			oids = append(oids, fillResultObject(obj, attributes))
		}
	}

	return oids, nil
}

func fillResultObject(obj *object.Object, attributes []string) client.SearchResultItem {
	resultItem := client.SearchResultItem{
		ID: obj.GetID(),
	}

	var attrMap = make(map[string]string, len(obj.Attributes()))
	for _, attr := range obj.Attributes() {
		attrMap[attr.Key()] = attr.Value()
	}

	resultItem.Attributes = make([]string, len(attributes))
	for i, attrName := range attributes {
		if v, ok := attrMap[attrName]; ok {
			resultItem.Attributes[i] = v
		}
	}

	return resultItem
}

func checkFilters(obj *object.Object, filters object.SearchFilters) bool {
	var isOk = true

	attrs := make(map[string]string, len(obj.Attributes()))
	for _, attr := range obj.Attributes() {
		attrs[attr.Key()] = attr.Value()
	}

	for _, f := range filters {
		val, present := attrs[f.Header()]

		switch f.Operation() {
		case object.MatchStringEqual:
			if f.Header() == "$Object:objectType" {
				isOk = isOk && obj.Type().String() == f.Value()
			} else {
				isOk = isOk && val == f.Value()
			}
		case object.MatchStringNotEqual:
			isOk = isOk && val != f.Value()
		case object.MatchCommonPrefix:
			isOk = isOk && strings.HasPrefix(val, f.Value())
		case object.MatchNotPresent:
			isOk = !present
		default:
			isOk = false
		}
	}

	return isOk
}
