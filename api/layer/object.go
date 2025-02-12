package layer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sio"
	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	"github.com/nspcc-dev/neofs-s3-gw/api/s3errors"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"go.uber.org/zap"
	"golang.org/x/exp/maps"
)

type (
	getParams struct {
		// payload range
		off, ln uint64

		oid     oid.ID
		bktInfo *data.BucketInfo
	}

	// ListObjectsParamsCommon contains common parameters for ListObjectsV1 and ListObjectsV2.
	ListObjectsParamsCommon struct {
		BktInfo   *data.BucketInfo
		Delimiter string
		Encode    string
		MaxKeys   int
		Prefix    string
	}

	// ListObjectsParamsV1 contains params for ListObjectsV1.
	ListObjectsParamsV1 struct {
		ListObjectsParamsCommon
		Marker string
	}

	// ListObjectsParamsV2 contains params for ListObjectsV2.
	ListObjectsParamsV2 struct {
		ListObjectsParamsCommon
		ContinuationToken string
		StartAfter        string
		FetchOwner        bool
	}

	allObjectParams struct {
		Bucket            *data.BucketInfo
		Delimiter         string
		Prefix            string
		MaxKeys           int
		Marker            string
		ContinuationToken string
	}

	prefixSearchResult struct {
		ID                oid.ID
		FilePath          string
		CreationEpoch     uint64
		CreationTimestamp int64
		IsDeleteMarker    bool
	}
)

const (
	continuationToken = "<continuation-token>"

	attrS3VersioningState = "S3-versioning-state"
	attrS3DeleteMarker    = "S3-delete-marker"
)

func newAddress(cnr cid.ID, obj oid.ID) oid.Address {
	var addr oid.Address
	addr.SetContainer(cnr)
	addr.SetObject(obj)
	return addr
}

// objectHead returns all object's headers.
func (n *layer) objectHead(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) (*object.Object, error) {
	prm := PrmObjectRead{
		Container:  bktInfo.CID,
		Object:     idObj,
		WithHeader: true,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	return res.Head, nil
}

// initializes payload reader of the NeoFS object.
// Zero range corresponds to full payload (panics if only offset is set).
func (n *layer) initObjectPayloadReader(ctx context.Context, p getParams) (io.Reader, error) {
	prm := PrmObjectRead{
		Container:    p.bktInfo.CID,
		Object:       p.oid,
		WithPayload:  true,
		PayloadRange: [2]uint64{p.off, p.ln},
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, p.bktInfo.Owner)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

// objectGet returns an object with payload in the object.
func (n *layer) objectGet(ctx context.Context, bktInfo *data.BucketInfo, objID oid.ID) (*object.Object, error) {
	prm := PrmObjectRead{
		Container:   bktInfo.CID,
		Object:      objID,
		WithHeader:  true,
		WithPayload: true,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	res, err := n.neoFS.ReadObject(ctx, prm)
	if err != nil {
		return nil, err
	}

	return res.Head, nil
}

// MimeByFilePath detect mime type by file path extension.
func MimeByFilePath(path string) string {
	ext := filepath.Ext(path)
	if len(ext) == 0 {
		return ""
	}
	return mime.TypeByExtension(ext)
}

func encryptionReader(r io.Reader, size uint64, key []byte) (io.Reader, uint64, error) {
	encSize, err := sio.EncryptedSize(size)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compute enc size: %w", err)
	}

	r, err = sio.EncryptReader(r, sio.Config{MinVersion: sio.Version20, MaxVersion: sio.Version20, Key: key, CipherSuites: []byte{sio.AES_256_GCM}})
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't create encrypter: %w", err)
	}

	return r, encSize, nil
}

func ParseCompletedPartHeader(hdr string) (*Part, error) {
	// partInfo[0] -- part number, partInfo[1] -- part size, partInfo[2] -- checksum
	partInfo := strings.Split(hdr, "-")
	if len(partInfo) != 3 {
		return nil, fmt.Errorf("invalid completed part header")
	}
	num, err := strconv.Atoi(partInfo[0])
	if err != nil {
		return nil, fmt.Errorf("invalid completed part number '%s': %w", partInfo[0], err)
	}
	size, err := strconv.Atoi(partInfo[1])
	if err != nil {
		return nil, fmt.Errorf("invalid completed part size '%s': %w", partInfo[1], err)
	}

	return &Part{
		ETag:       partInfo[2],
		PartNumber: num,
		Size:       int64(size),
	}, nil
}

// PutObject stores object into NeoFS, took payload from io.Reader.
//
// Returns [ErrMetaEmptyParameterValue] error if any attribute parameter is empty.
func (n *layer) PutObject(ctx context.Context, p *PutObjectParams) (*data.ExtendedObjectInfo, error) {
	owner := n.Owner(ctx)

	bktSettings, err := n.GetBucketSettings(ctx, p.BktInfo)
	if err != nil {
		return nil, fmt.Errorf("couldn't get versioning settings object: %w", err)
	}

	newVersion := &data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			FilePath: p.Object,
			Size:     p.Size,
		},
		IsUnversioned: !bktSettings.VersioningEnabled(),
	}

	r := p.Reader
	if p.Encryption.Enabled() {
		p.Header[AttributeDecryptedSize] = strconv.FormatInt(p.Size, 10)
		if err = addEncryptionHeaders(p.Header, p.Encryption); err != nil {
			return nil, fmt.Errorf("add encryption header: %w", err)
		}

		var encSize uint64
		if r, encSize, err = encryptionReader(p.Reader, uint64(p.Size), p.Encryption.Key()); err != nil {
			return nil, fmt.Errorf("create encrypter: %w", err)
		}
		p.Size = int64(encSize)
	}

	if r != nil {
		if len(p.Header[api.ContentType]) == 0 {
			if contentType := MimeByFilePath(p.Object); len(contentType) == 0 {
				d := newDetector(r)
				if contentType, err := d.Detect(); err == nil {
					p.Header[api.ContentType] = contentType
				}
				r = d.MultiReader()
			} else {
				p.Header[api.ContentType] = contentType
			}
		}
	}

	for _, v := range p.Header {
		if v == "" {
			return nil, ErrMetaEmptyParameterValue
		}
	}

	prm := PrmObjectCreate{
		Container:    p.BktInfo.CID,
		Creator:      owner,
		PayloadSize:  uint64(p.Size),
		Filepath:     p.Object,
		Payload:      r,
		CreationTime: TimeNow(ctx),
		CopiesNumber: p.CopiesNumber,
		Attributes:   p.Header,
	}

	if bktSettings.VersioningEnabled() {
		prm.Attributes[attrS3VersioningState] = data.VersioningEnabled
	}

	id, hash, err := n.objectPutAndHash(ctx, prm, p.BktInfo)
	if err != nil {
		return nil, err
	}

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("put object",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", p.BktInfo.Name), zap.Stringer("cid", p.BktInfo.CID),
		zap.String("object", p.Object), zap.Stringer("oid", id), zap.Int64("size", p.Size))

	newVersion.OID = id
	newVersion.ETag = hex.EncodeToString(hash)

	if p.Lock != nil && (p.Lock.Retention != nil || p.Lock.LegalHold != nil) {
		putLockInfoPrms := &PutLockInfoParams{
			ObjVersion: &ObjectVersion{
				BktInfo:    p.BktInfo,
				ObjectName: p.Object,
			},
			NewLock:      p.Lock,
			CopiesNumber: p.CopiesNumber,
		}

		if bktSettings.VersioningEnabled() {
			putLockInfoPrms.ObjVersion.VersionID = id.String()
		}

		if err = n.PutLockInfo(ctx, putLockInfoPrms); err != nil {
			return nil, err
		}
	}

	n.cache.CleanListCacheEntriesContainingObject(p.Object, p.BktInfo.CID)

	objInfo := &data.ObjectInfo{
		ID:  id,
		CID: p.BktInfo.CID,

		Owner:          owner,
		OwnerPublicKey: p.BktInfo.OwnerPublicKey,
		Bucket:         p.BktInfo.Name,
		Name:           p.Object,
		Size:           p.Size,
		Created:        prm.CreationTime,
		Headers:        p.Header,
		ContentType:    p.Header[api.ContentType],
		HashSum:        newVersion.ETag,
	}

	extendedObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: newVersion,
	}

	n.cache.PutObjectWithName(owner, extendedObjInfo)

	return extendedObjInfo, nil
}

func (n *layer) prepareMultipartHeadObject(ctx context.Context, p *PutObjectParams, payloadHash hash.Hash, homoHash hash.Hash, payloadLength uint64, versioningEnabled bool) (*object.Object, error) {
	var (
		err   error
		owner = n.Owner(ctx)
	)

	if p.Encryption.Enabled() {
		p.Header[AttributeDecryptedSize] = strconv.FormatInt(p.Size, 10)
		if err = addEncryptionHeaders(p.Header, p.Encryption); err != nil {
			return nil, fmt.Errorf("add encryption header: %w", err)
		}

		var encSize uint64
		if _, encSize, err = encryptionReader(p.Reader, uint64(p.Size), p.Encryption.Key()); err != nil {
			return nil, fmt.Errorf("create encrypter: %w", err)
		}
		p.Size = int64(encSize)
	}

	var headerObject object.Object
	headerObject.SetContainerID(p.BktInfo.CID)
	headerObject.SetType(object.TypeRegular)
	headerObject.SetOwnerID(&owner)

	currentVersion := version.Current()
	headerObject.SetVersion(&currentVersion)

	attributes := make([]object.Attribute, 0, len(p.Header))
	for k, v := range p.Header {
		if v == "" {
			return nil, ErrMetaEmptyParameterValue
		}

		attributes = append(attributes, *object.NewAttribute(k, v))
	}

	creationTime := TimeNow(ctx)
	if creationTime.IsZero() {
		creationTime = time.Now()
	}
	attributes = append(attributes, *object.NewAttribute(object.AttributeTimestamp, strconv.FormatInt(creationTime.Unix(), 10)))

	if p.Object != "" {
		attributes = append(attributes, *object.NewAttribute(object.AttributeFilePath, p.Object))
	}

	if versioningEnabled {
		attributes = append(attributes, *object.NewAttribute(attrS3VersioningState, data.VersioningEnabled))
	}

	headerObject.SetAttributes(attributes...)

	multipartHeader, err := n.neoFS.FinalizeObjectWithPayloadChecksums(ctx, headerObject, payloadHash, homoHash, payloadLength)
	if err != nil {
		return nil, fmt.Errorf("FinalizeObjectWithPayloadChecksums: %w", err)
	}

	return multipartHeader, nil
}

func (n *layer) headLastVersionIfNotDeleted(ctx context.Context, bkt *data.BucketInfo, objectName string) (*data.ExtendedObjectInfo, error) {
	owner := n.Owner(ctx)
	if extObjInfo := n.cache.GetLastObject(owner, bkt.Name, objectName); extObjInfo != nil {
		return extObjInfo, nil
	}

	heads, err := n.searchAllVersionsInNeoFS(ctx, bkt, owner, objectName, false)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
		}
		return nil, err
	}

	if isDeleteMarkerObject(*heads[0]) {
		return nil, s3errors.GetAPIError(s3errors.ErrNoSuchKey)
	}

	objInfo := objectInfoFromMeta(bkt, heads[0]) // latest version.

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: &data.NodeVersion{},
	}

	n.cache.PutObjectWithName(owner, extObjInfo)

	return extObjInfo, nil
}

// searchAllVersionsInNeoFS returns all version of object by its objectName.
//
// Returns ErrNodeNotFound if zero objects found.
func (n *layer) searchAllVersionsInNeoFS(ctx context.Context, bkt *data.BucketInfo, owner user.ID, objectName string, onlyUnversioned bool) ([]*object.Object, error) {
	prmSearch := PrmObjectSearch{
		Container: bkt.CID,
		Filters:   make(object.SearchFilters, 0, 4),
	}

	n.prepareAuthParameters(ctx, &prmSearch.PrmAuth, owner)
	prmSearch.Filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	prmSearch.Filters.AddFilter(attributeTagsMetaObject, "", object.MatchNotPresent)

	if len(objectName) > 0 {
		prmSearch.Filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	}

	if onlyUnversioned {
		prmSearch.Filters.AddFilter(attrS3VersioningState, data.VersioningUnversioned, object.MatchNotPresent)
	}

	return n.searchObjects(ctx, bkt, prmSearch)
}

// searchAllVersionsInNeoFS returns all version of object by its objectName.
//
// Returns ErrNodeNotFound if zero objects found.
func (n *layer) searchAllVersionsInNeoFSByPrefix(ctx context.Context, bkt *data.BucketInfo, owner user.ID, prefix string, onlyUnversioned bool) ([]prefixSearchResult, error) {
	var (
		filters             = make(object.SearchFilters, 0, 4)
		returningAttributes = []string{
			object.FilterCreationEpoch,
			object.AttributeFilePath,
			object.AttributeTimestamp,
			attrS3DeleteMarker,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(object.FilterCreationEpoch, "0", object.MatchNumGT)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)

	if len(prefix) > 0 {
		filters.AddFilter(object.AttributeFilePath, prefix, object.MatchCommonPrefix)
	}

	filters.AddFilter(attributeTagsMetaObject, "", object.MatchNotPresent)

	if onlyUnversioned {
		filters.AddFilter(attrS3VersioningState, data.VersioningUnversioned, object.MatchNotPresent)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bkt.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("search objects: %w", err)
	}

	if len(searchResultItems) == 0 {
		return nil, ErrNodeNotFound
	}

	var searchResults = make([]prefixSearchResult, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return nil, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = prefixSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[1],
		}

		if item.Attributes[0] != "" {
			psr.CreationEpoch, err = strconv.ParseUint(item.Attributes[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid creation epoch %s: %w", item.Attributes[0], err)
			}
		}

		if item.Attributes[2] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[2], err)
			}
		}

		psr.IsDeleteMarker = item.Attributes[3] != ""

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b prefixSearchResult) int {
		if c := cmp.Compare(b.CreationEpoch, a.CreationEpoch); c != 0 { // reverse order.
			return c
		}

		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	slices.SortFunc(searchResults, sortFunc)

	return searchResults, nil
}

func (n *layer) searchObjects(ctx context.Context, bkt *data.BucketInfo, prmSearch PrmObjectSearch) ([]*object.Object, error) {
	ids, err := n.neoFS.SearchObjects(ctx, prmSearch)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("search object version: %w", err)
	}

	if len(ids) == 0 {
		return nil, ErrNodeNotFound
	}

	var heads = make([]*object.Object, 0, len(ids))

	for i := range ids {
		head, err := n.objectHead(ctx, bkt, ids[i])
		if err != nil {
			n.log.Warn("couldn't head object",
				zap.Stringer("oid", &ids[i]),
				zap.Stringer("cid", bkt.CID),
				zap.Error(err))

			return nil, fmt.Errorf("couldn't head object: %w", err)
		}

		// The object is a part of split chain, it doesn't exist for user.
		if head.HasParent() {
			continue
		}

		heads = append(heads, head)
	}

	slices.SortFunc(heads, sortObjectsFunc)

	return heads, nil
}

func sortObjectsFunc(a, b *object.Object) int {
	if c := cmp.Compare(b.CreationEpoch(), a.CreationEpoch()); c != 0 { // reverse order.
		return c
	}

	var (
		aCreated int64
		bCreated int64
	)

	for _, attr := range a.Attributes() {
		if attr.Key() == object.AttributeTimestamp {
			aCreated, _ = strconv.ParseInt(attr.Value(), 10, 64)
			break
		}
	}
	for _, attr := range b.Attributes() {
		if attr.Key() == object.AttributeTimestamp {
			bCreated, _ = strconv.ParseInt(attr.Value(), 10, 64)
			break
		}
	}

	if c := cmp.Compare(bCreated, aCreated); c != 0 { // reverse order.
		return c
	}

	bID := b.GetID()
	aID := a.GetID()

	// It is a temporary decision. We can't figure out what object was first and what the second right now.
	return bytes.Compare(bID[:], aID[:]) // reverse order.
}

func sortObjectsFuncByFilePath(a, b *object.Object) int {
	var aPath string
	var bPath string

	for _, attr := range a.Attributes() {
		if attr.Key() == object.AttributeFilePath {
			aPath = attr.Value()
		}
	}
	for _, attr := range b.Attributes() {
		if attr.Key() == object.AttributeFilePath {
			bPath = attr.Value()
		}
	}

	return cmp.Compare(aPath, bPath)
}

func (n *layer) searchLatestVersionsByPrefix(ctx context.Context, bkt *data.BucketInfo, owner user.ID, prefix string, onlyUnversioned bool) ([]prefixSearchResult, error) {
	searchResults, err := n.searchAllVersionsInNeoFSByPrefix(ctx, bkt, owner, prefix, onlyUnversioned)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("get all versions by prefix: %w", err)
	}

	var uniq = make(map[string]prefixSearchResult, len(searchResults))

	for _, result := range searchResults {
		// take only first object, because it is the freshest one.
		if _, ok := uniq[result.FilePath]; !ok {
			uniq[result.FilePath] = result
		}
	}

	return maps.Values(uniq), nil
}

func (n *layer) headVersion(ctx context.Context, bkt *data.BucketInfo, p *HeadObjectParams) (*data.ExtendedObjectInfo, error) {
	var err error
	var foundVersion *object.Object
	if p.VersionID == data.UnversionedObjectVersionID {
		versions, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, p.Object, true)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
			}
			return nil, err
		}

		foundVersion = versions[0]
	} else {
		versions, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, p.Object, false)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
			}
			return nil, err
		}

		if p.IsBucketVersioningEnabled {
			for _, version := range versions {
				if version.GetID().EncodeToString() == p.VersionID {
					foundVersion = version
					break
				}
			}
		} else {
			// If versioning is not enabled, user "should see" only last version of uploaded object.
			if versions[0].GetID().EncodeToString() == p.VersionID {
				foundVersion = versions[0]
			}
		}
		if foundVersion == nil {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
		}
	}

	id := foundVersion.GetID()
	owner := n.Owner(ctx)
	if extObjInfo := n.cache.GetObject(owner, newAddress(bkt.CID, id)); extObjInfo != nil {
		return extObjInfo, nil
	}

	meta, err := n.objectHead(ctx, bkt, id)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectNotFound) {
			return nil, s3errors.GetAPIError(s3errors.ErrNoSuchVersion)
		}
		return nil, err
	}
	objInfo := objectInfoFromMeta(bkt, meta)

	extObjInfo := &data.ExtendedObjectInfo{
		ObjectInfo:  objInfo,
		NodeVersion: &data.NodeVersion{},
	}

	n.cache.PutObject(owner, extObjInfo)

	return extObjInfo, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) error {
	prm := PrmObjectDelete{
		Container: bktInfo.CID,
		Object:    idObj,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	n.cache.DeleteObject(newAddress(bktInfo.CID, idObj))

	err := n.neoFS.DeleteObject(ctx, prm)

	reqInfo := api.GetReqInfo(ctx)
	n.log.Debug("delete object",
		zap.String("reqId", reqInfo.RequestID),
		zap.String("bucket", bktInfo.Name),
		zap.Stringer("cid", bktInfo.CID),
		zap.Stringer("oid", idObj),
		zap.Error(err),
	)

	return err
}

// objectPutAndHash prepare auth parameters and invoke neofs.CreateObject.
// Returns object ID and payload sha256 hash.
func (n *layer) objectPutAndHash(ctx context.Context, prm PrmObjectCreate, bktInfo *data.BucketInfo) (oid.ID, []byte, error) {
	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)
	hash := sha256.New()

	if prm.Payload != nil {
		prm.Payload = io.TeeReader(prm.Payload, hash)
	}

	id, err := n.neoFS.CreateObject(ctx, prm)
	if err != nil {
		return oid.ID{}, nil, err
	}
	return id, hash.Sum(nil), nil
}

// multipartObjectPut writes only Multipart hash collection.
// It doesn't calculate hash from payload, it already calculated in prm.Multipart.PayloadHash, if required.
func (n *layer) multipartObjectPut(ctx context.Context, prm PrmObjectCreate, bktInfo *data.BucketInfo) (oid.ID, error) {
	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	if prm.Multipart != nil && prm.Payload != nil {
		var writers = make([]io.Writer, len(prm.Multipart.MultipartHashes))
		for i, h := range prm.Multipart.MultipartHashes {
			writers[i] = h
		}

		w := io.MultiWriter(writers...)
		prm.Payload = io.TeeReader(prm.Payload, w)
	}

	id, err := n.neoFS.CreateObject(ctx, prm)
	if err != nil {
		return oid.ID{}, err
	}
	return id, nil
}

// ListObjectsV1 returns objects in a bucket for requests of Version 1.
func (n *layer) ListObjectsV1(ctx context.Context, p *ListObjectsParamsV1) (*ListObjectsInfoV1, error) {
	var result ListObjectsInfoV1

	prm := allObjectParams{
		Bucket:    p.BktInfo,
		Delimiter: p.Delimiter,
		Prefix:    p.Prefix,
		MaxKeys:   p.MaxKeys,
		Marker:    p.Marker,
	}

	objects, next, err := n.getLatestObjectsVersions(ctx, prm)
	if err != nil {
		return nil, err
	}

	if next != nil {
		result.IsTruncated = true
		result.NextMarker = objects[len(objects)-1].Name
	}

	result.Prefixes, result.Objects = triageObjects(objects)

	return &result, nil
}

// ListObjectsV2 returns objects in a bucket for requests of Version 2.
func (n *layer) ListObjectsV2(ctx context.Context, p *ListObjectsParamsV2) (*ListObjectsInfoV2, error) {
	var result ListObjectsInfoV2

	prm := allObjectParams{
		Bucket:            p.BktInfo,
		Delimiter:         p.Delimiter,
		Prefix:            p.Prefix,
		MaxKeys:           p.MaxKeys,
		Marker:            p.StartAfter,
		ContinuationToken: p.ContinuationToken,
	}

	objects, next, err := n.getLatestObjectsVersions(ctx, prm)
	if err != nil {
		return nil, err
	}

	if next != nil {
		result.IsTruncated = true
		result.NextContinuationToken = next.ID.EncodeToString()
	}

	result.Prefixes, result.Objects = triageObjects(objects)

	return &result, nil
}

func (n *layer) getLatestObjectsVersions(ctx context.Context, p allObjectParams) (objects []data.ObjectListResponseContent, next *data.ObjectListResponseContent, err error) {
	if p.MaxKeys == 0 {
		return nil, nil, nil
	}

	owner := n.Owner(ctx)
	cacheKey := cache.CreateObjectsListCacheKey(p.Bucket.CID, p.Prefix, true)
	nodeVersions := n.cache.GetList(owner, cacheKey)

	var latestVersions []prefixSearchResult

	if nodeVersions == nil {
		latestVersions, err = n.searchLatestVersionsByPrefix(ctx, p.Bucket, p.Bucket.Owner, p.Prefix, false)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, nil, nil
			}

			return nil, nil, err
		}
	}

	if len(latestVersions) == 0 {
		return nil, nil, nil
	}

	sortFunc := func(a, b prefixSearchResult) int {
		return cmp.Compare(a.FilePath, b.FilePath)
	}

	slices.SortFunc(latestVersions, sortFunc)
	existed := make(map[string]struct{}, len(nodeVersions)) // to squash the same directories

	for _, ver := range latestVersions {
		if shouldSkip(ver, p, existed) {
			continue
		}

		var oi *data.ObjectListResponseContent

		if oi = tryDirectoryFromObject(p.Prefix, p.Delimiter, ver.FilePath); oi == nil {
			head, err := n.objectHead(ctx, p.Bucket, ver.ID)
			if err != nil {
				if isErrObjectAlreadyRemoved(err) {
					continue
				}

				return nil, nil, fmt.Errorf("head details: %w", err)
			}

			var (
				attributeDecryptedSize int64
			)

			for _, attr := range head.Attributes() {
				if attr.Key() == AttributeDecryptedSize {
					if attributeDecryptedSize, err = strconv.ParseInt(attr.Value(), 10, 64); err != nil {
						return nil, nil, fmt.Errorf("parse decrypted size %s: %w", attr.Value(), err)
					}

					break
				}
			}

			payloadChecksum, _ := head.PayloadChecksum()

			oi = &data.ObjectListResponseContent{
				ID:      ver.ID,
				Owner:   p.Bucket.Owner,
				Created: time.Unix(ver.CreationTimestamp, 0),
				Name:    ver.FilePath,

				DecryptedSize: attributeDecryptedSize,
				Size:          int64(head.PayloadSize()),
				HashSum:       hex.EncodeToString(payloadChecksum.Value()),
			}
		}

		objects = append(objects, *oi)
	}

	slices.SortFunc(objects, func(a, b data.ObjectListResponseContent) int {
		return cmp.Compare(a.Name, b.Name)
	})

	if len(objects) > p.MaxKeys {
		next = &objects[p.MaxKeys]
		objects = objects[:p.MaxKeys]
	}

	return
}

func (n *layer) getAllObjectsVersions(ctx context.Context, bkt *data.BucketInfo, prefix, delimiter string) (map[string][]*data.ExtendedObjectInfo, error) {
	nodeVersions, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, prefix, false)
	if err != nil {
		return nil, err
	}

	versions := make(map[string][]*data.ExtendedObjectInfo, len(nodeVersions))

	for _, nodeVersion := range nodeVersions {
		oi := &data.ObjectInfo{}

		if isDeleteMarkerObject(*nodeVersion) {
			oi.ID = nodeVersion.GetID()
			oi.Name = filepathFromObject(nodeVersion)
			oi.Size = int64(nodeVersion.PayloadSize())
			if owner := nodeVersion.OwnerID(); owner != nil {
				oi.Owner = *owner
			}

			for _, attr := range nodeVersion.Attributes() {
				if attr.Key() == object.AttributeTimestamp {
					ts, err := strconv.ParseInt(attr.Value(), 10, 64)
					if err != nil {
						return nil, err
					}

					oi.Created = time.Unix(ts, 0)
					break
				}
			}

			oi.IsDeleteMarker = true
		} else {
			nv := data.NodeVersion{
				BaseNodeVersion: data.BaseNodeVersion{
					OID:      nodeVersion.GetID(),
					FilePath: prefix,
				},
			}

			state := getS3VersioningState(*nodeVersion)
			nv.IsUnversioned = state == data.VersioningUnversioned

			if oi = n.objectInfoFromObjectsCacheOrNeoFS(ctx, bkt, &nv, prefix, delimiter); oi == nil {
				continue
			}
		}

		state := getS3VersioningState(*nodeVersion)

		eoi := &data.ExtendedObjectInfo{
			ObjectInfo: oi,
			NodeVersion: &data.NodeVersion{
				BaseNodeVersion: data.BaseNodeVersion{
					ID:        0,
					ParenID:   0,
					OID:       oi.ID,
					Timestamp: uint64(oi.Created.Unix()),
					Size:      0,
					ETag:      "",
					FilePath:  oi.Name,
				},
				IsUnversioned: state == data.VersioningUnversioned,
			},
		}

		if oi.IsDeleteMarker {
			eoi.NodeVersion.DeleteMarker = &data.DeleteMarkerInfo{
				Created: oi.Created,
				Owner:   *nodeVersion.OwnerID(),
			}
		}

		objVersions, ok := versions[oi.Name]
		if !ok {
			objVersions = []*data.ExtendedObjectInfo{eoi}
		} else if !oi.IsDir {
			objVersions = append(objVersions, eoi)
		}
		versions[oi.Name] = objVersions
	}

	return versions, nil
}

func IsSystemHeader(key string) bool {
	_, ok := api.SystemMetadata[key]
	return ok || strings.HasPrefix(key, api.NeoFSSystemMetadataPrefix)
}

func shouldSkip(result prefixSearchResult, p allObjectParams, existed map[string]struct{}) bool {
	if result.IsDeleteMarker {
		return true
	}

	filePath := result.FilePath
	if dirName := tryDirectoryName(result.FilePath, p.Prefix, p.Delimiter); len(dirName) != 0 {
		filePath = dirName
	}
	if _, ok := existed[filePath]; ok {
		return true
	}

	if filePath <= p.Marker {
		return true
	}

	if p.ContinuationToken != "" {
		if _, ok := existed[continuationToken]; !ok {
			if p.ContinuationToken != result.ID.EncodeToString() {
				return true
			}
			existed[continuationToken] = struct{}{}
		}
	}

	existed[filePath] = struct{}{}
	return false
}

func triageObjects(allObjects []data.ObjectListResponseContent) (prefixes []string, objects []data.ObjectListResponseContent) {
	for _, ov := range allObjects {
		if ov.IsDir {
			prefixes = append(prefixes, ov.Name)
		} else {
			objects = append(objects, ov)
		}
	}

	return
}

func triageExtendedObjects(allObjects []*data.ExtendedObjectInfo) (prefixes []string, objects []*data.ExtendedObjectInfo) {
	for _, ov := range allObjects {
		if ov.ObjectInfo.IsDir {
			prefixes = append(prefixes, ov.ObjectInfo.Name)
		} else {
			objects = append(objects, ov)
		}
	}

	return
}

func (n *layer) objectInfoFromObjectsCacheOrNeoFS(ctx context.Context, bktInfo *data.BucketInfo, node *data.NodeVersion, prefix, delimiter string) (oi *data.ObjectInfo) {
	if oiDir := tryDirectory(bktInfo, node, prefix, delimiter); oiDir != nil {
		return oiDir
	}

	owner := n.Owner(ctx)
	if extInfo := n.cache.GetObject(owner, newAddress(bktInfo.CID, node.OID)); extInfo != nil {
		return extInfo.ObjectInfo
	}

	meta, err := n.objectHead(ctx, bktInfo, node.OID)
	if err != nil {
		n.log.Warn("could not fetch object meta", zap.Error(err))
		return nil
	}

	oi = objectInfoFromMeta(bktInfo, meta)
	n.cache.PutObject(owner, &data.ExtendedObjectInfo{ObjectInfo: oi, NodeVersion: node})

	return oi
}

func tryDirectory(bktInfo *data.BucketInfo, node *data.NodeVersion, prefix, delimiter string) *data.ObjectInfo {
	dirName := tryDirectoryName(node.FilePath, prefix, delimiter)
	if len(dirName) == 0 {
		return nil
	}

	return &data.ObjectInfo{
		ID:             node.OID, // to use it as continuation token
		CID:            bktInfo.CID,
		IsDir:          true,
		IsDeleteMarker: node.IsDeleteMarker(),
		Bucket:         bktInfo.Name,
		Name:           dirName,
	}
}

func tryDirectoryFromObject(prefix, delimiter string, filePath string) *data.ObjectListResponseContent {
	dirName := tryDirectoryName(filePath, prefix, delimiter)
	if len(dirName) == 0 {
		return nil
	}

	return &data.ObjectListResponseContent{
		IsDir: true,
		Name:  dirName,
	}
}

// tryDirectoryName forms directory name by prefix and delimiter.
// If node isn't a directory empty string is returned.
// This function doesn't check if node has a prefix. It must do a caller.
func tryDirectoryName(filePath string, prefix, delimiter string) string {
	if len(delimiter) == 0 {
		return ""
	}

	tail := strings.TrimPrefix(filePath, prefix)
	index := strings.Index(tail, delimiter)
	if index >= 0 {
		return prefix + tail[:index+1]
	}

	return ""
}

func convert(head object.Object) data.NodeVersion {
	nv := data.NodeVersion{
		BaseNodeVersion: data.BaseNodeVersion{
			OID: head.GetID(),
		},
	}

	for _, attr := range head.Attributes() {
		switch attr.Key() {
		case object.AttributeFilePath:
			nv.BaseNodeVersion.FilePath = attr.Value()
		case attrS3DeleteMarker:
			nv.DeleteMarker = &data.DeleteMarkerInfo{
				Created: time.Time{},
				Owner:   *head.OwnerID(),
			}
		}
	}

	return nv
}

func filePathFromAttributes(head object.Object) string {
	for _, attr := range head.Attributes() {
		if attr.Key() == object.AttributeFilePath {
			return attr.Value()
		}
	}

	return ""
}
