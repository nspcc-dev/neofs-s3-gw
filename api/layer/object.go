package layer

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"mime"
	"net/url"
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
	"github.com/nspcc-dev/neofs-s3-gw/api/s3headers"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"go.uber.org/zap"
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
		CreationTimestamp int64
		IsDeleteMarker    bool
		DecryptedSize     int64
		PayloadSize       int64
		PayloadChecksum   string
	}

	versioningContainerIDSearchResult struct {
		ID                oid.ID
		FilePath          string
		CreationTimestamp int64
		IsDeleteMarker    bool
	}

	allVersionsSearchResult struct {
		ID                oid.ID
		FilePath          string
		CreationTimestamp int64
		PayloadSize       int64
		IsDeleteMarker    bool
		IsVersioned       bool
	}

	baseSearchResult struct {
		ID                oid.ID
		CreationTimestamp int64
	}
)

func (a prefixSearchResult) isNewerThan(b prefixSearchResult) bool {
	return a.CreationTimestamp > b.CreationTimestamp
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
		FilePath:      p.Object,
		IsUnversioned: !bktSettings.VersioningEnabled(),
	}

	r := p.Reader
	if p.Encryption.Enabled() {
		p.Header[s3headers.AttributeDecryptedSize] = strconv.FormatInt(p.Size, 10)
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

	for k, v := range p.Tags {
		p.Header[s3headers.NeoFSSystemMetadataTagPrefix+k] = v
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
		prm.Attributes[s3headers.AttributeVersioningState] = data.VersioningEnabled
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
		p.Header[s3headers.AttributeDecryptedSize] = strconv.FormatInt(p.Size, 10)
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
	headerObject.SetOwner(owner)

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
		attributes = append(attributes, *object.NewAttribute(s3headers.AttributeVersioningState, data.VersioningEnabled))
	}

	headerObject.SetAttributes(attributes...)

	multipartHeader, err := n.neoFS.FinalizeObjectWithPayloadChecksums(ctx, headerObject, payloadHash, homoHash, payloadLength)
	if err != nil {
		return nil, fmt.Errorf("FinalizeObjectWithPayloadChecksums: %w", err)
	}

	return multipartHeader, nil
}

// searchAllVersionsInNeoFS returns all version of object by its objectName.
//
// Returns ErrNodeNotFound if zero objects found.
func (n *layer) searchAllVersionsInNeoFS(ctx context.Context, bkt *data.BucketInfo, owner user.ID, objectName string, onlyUnversioned bool) ([]allVersionsSearchResult, error) {
	var (
		filters             = make(object.SearchFilters, 0, 6)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.AttributeTimestamp,
			s3headers.AttributeVersioningState,
			object.FilterPayloadSize,
			s3headers.AttributeDeleteMarker,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	if len(objectName) > 0 {
		filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	} else {
		filters.AddFilter(object.AttributeFilePath, "", object.MatchCommonPrefix)
	}

	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	filters.AddFilter(s3headers.MetaType, "", object.MatchNotPresent)

	if onlyUnversioned {
		filters.AddFilter(s3headers.AttributeVersioningState, "", object.MatchNotPresent)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bkt.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		return nil, ErrNodeNotFound
	}

	var searchResults = make([]allVersionsSearchResult, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return nil, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = allVersionsSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		psr.IsVersioned = item.Attributes[2] == data.VersioningEnabled

		if item.Attributes[3] != "" {
			psr.PayloadSize, err = strconv.ParseInt(item.Attributes[3], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid payload size %s: %w", item.Attributes[3], err)
			}
		}

		psr.IsDeleteMarker = item.Attributes[4] != ""

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b allVersionsSearchResult) int {
		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	slices.SortFunc(searchResults, sortFunc)

	return searchResults, nil
}

func (n *layer) comprehensiveSearchAllVersionsInNeoFS(ctx context.Context, bkt *data.BucketInfo, owner user.ID, objectName string, onlyUnversioned bool) ([]allVersionsSearchResult, oid.ID, *data.LockInfo, error) {
	var (
		filters             = make(object.SearchFilters, 0, 7)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.AttributeTimestamp,
			s3headers.AttributeVersioningState,
			s3headers.AttributeDeleteMarker,
			s3headers.MetaType,
			s3headers.AttributeObjectVersion,
			object.AttributeExpirationEpoch,
			s3headers.AttributeLockMeta,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	if len(objectName) > 0 {
		filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	} else {
		filters.AddFilter(object.AttributeFilePath, "", object.MatchCommonPrefix)
	}

	if onlyUnversioned {
		filters.AddFilter(s3headers.AttributeVersioningState, "", object.MatchNotPresent)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bkt.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, oid.ID{}, nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, oid.ID{}, nil, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		return nil, oid.ID{}, nil, ErrNodeNotFound
	}

	var (
		searchResults   = make([]allVersionsSearchResult, 0, len(searchResultItems))
		locksByVersions = make(map[string][]locksSearchResult)
		lockInfo        *data.LockInfo
		tagsObjectOID   allVersionsSearchResult
		tagsByVersion   = make(map[string]allVersionsSearchResult)
	)

	sortFunc := func(a, b allVersionsSearchResult) int {
		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return nil, oid.ID{}, nil, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = allVersionsSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return nil, oid.ID{}, nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		var version = item.Attributes[5]

		switch item.Attributes[4] {
		case s3headers.TypeTags:
			tagResult, ok := tagsByVersion[version]
			if !ok || psr.CreationTimestamp > tagResult.CreationTimestamp {
				tagsByVersion[version] = psr
				continue
			}
		default:
			// lock meta object.
			if item.Attributes[7] != "" {
				var lsr = locksSearchResult{
					ID:                item.ID,
					FilePath:          item.Attributes[0],
					CreationTimestamp: psr.CreationTimestamp,
				}

				if item.Attributes[6] != "" {
					lsr.ExpirationEpoch, err = strconv.ParseUint(item.Attributes[6], 10, 64)
					if err != nil {
						return nil, oid.ID{}, nil, fmt.Errorf("invalid expiration epoch %s: %w", item.Attributes[6], err)
					}
				}

				if err = extractLockDataFromAttrubute(&lsr, item.Attributes[7]); err != nil {
					return nil, oid.ID{}, nil, fmt.Errorf("extract lock data from attrubute: %w", err)
				}

				if _, ok := locksByVersions[version]; !ok {
					locksByVersions[version] = make([]locksSearchResult, 1)
				}

				locksByVersions[version] = append(locksByVersions[version], lsr)
				continue
			}
		}

		psr.IsVersioned = item.Attributes[2] == data.VersioningEnabled
		psr.IsDeleteMarker = item.Attributes[3] != ""

		searchResults = append(searchResults, psr)
	}

	slices.SortFunc(searchResults, sortFunc)

	if len(searchResults) > 0 {
		var lockVersions []locksSearchResult

		if searchResults[0].IsVersioned {
			var ver = searchResults[0].ID.EncodeToString()

			tagsObjectOID = tagsByVersion[ver]
			lockVersions = locksByVersions[ver]
		} else {
			// empty version
			tagsObjectOID = tagsByVersion[""]
			lockVersions = locksByVersions[""]
		}

		slices.SortFunc(lockVersions, locksSearchResultsSortFunc)
		lockInfo = extractLockInfoFromSearch(lockVersions)
	}

	return searchResults, tagsObjectOID.ID, lockInfo, nil
}

func (n *layer) searchTagsAndLocksInNeoFS(ctx context.Context, bkt *data.BucketInfo, owner user.ID, objectName, objectVersion string) (oid.ID, *data.LockInfo, error) {
	var (
		filters             = make(object.SearchFilters, 0, 4)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.AttributeTimestamp,
			s3headers.MetaType,
			object.AttributeExpirationEpoch,
			s3headers.AttributeLockMeta,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	if len(objectName) > 0 {
		filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	} else {
		filters.AddFilter(object.AttributeFilePath, "", object.MatchCommonPrefix)
	}

	filters.AddFilter(s3headers.AttributeVersioningState, data.VersioningEnabled, object.MatchStringEqual)
	filters.AddFilter(s3headers.AttributeObjectVersion, objectVersion, object.MatchStringEqual)

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bkt.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return oid.ID{}, nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return oid.ID{}, nil, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		return oid.ID{}, nil, nil
	}

	var (
		tagResult         locksSearchResult
		lockSearchResults = make([]locksSearchResult, 0, len(searchResultItems))
	)

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return oid.ID{}, nil, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = locksSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return oid.ID{}, nil, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		switch item.Attributes[2] {
		case s3headers.TypeTags:
			if psr.CreationTimestamp > tagResult.CreationTimestamp {
				tagResult = psr
			}
		default:
			// it is a regular object, skip it.
			if item.Attributes[4] == "" {
				continue
			}

			// lock meta object.
			if err = extractLockDataFromAttrubute(&psr, item.Attributes[4]); err != nil {
				return oid.ID{}, nil, fmt.Errorf("extract lock data from attrubute: %w", err)
			}

			if item.Attributes[3] != "" {
				psr.ExpirationEpoch, err = strconv.ParseUint(item.Attributes[3], 10, 64)
				if err != nil {
					return oid.ID{}, nil, fmt.Errorf("invalid expiration epoch %s: %w", item.Attributes[3], err)
				}
			}

			lockSearchResults = append(lockSearchResults, psr)
		}
	}

	slices.SortFunc(lockSearchResults, locksSearchResultsSortFunc)
	lock := extractLockInfoFromSearch(lockSearchResults)

	return tagResult.ID, lock, nil
}

// searchAllVersionsInNeoFS returns all version of object by its objectName.
//
// Returns ErrNodeNotFound if zero objects found.
func (n *layer) searchAllVersionsInNeoFSByPrefix(ctx context.Context, bkt *data.BucketInfo, owner user.ID, prefix, cursor string, maxKeys int) ([]prefixSearchResult, string, error) {
	var (
		filters             = make(object.SearchFilters, 0, 3)
		returningAttributes = []string{
			object.AttributeFilePath,
			object.AttributeTimestamp,
			s3headers.AttributeDeleteMarker,
			s3headers.AttributeDecryptedSize,
			object.FilterPayloadSize,
			object.FilterPayloadChecksum,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	if maxKeys <= 0 || maxKeys > 1000 {
		maxKeys = 1000
	}

	opts.SetCount(uint32(maxKeys))

	filters.AddFilter(object.AttributeFilePath, prefix, object.MatchCommonPrefix)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	filters.AddFilter(s3headers.MetaType, "", object.MatchNotPresent)

	searchResultItems, nextCursor, err := n.neoFS.SearchObjectsV2WithCursor(ctx, bkt.CID, filters, returningAttributes, cursor, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, "", s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, "", fmt.Errorf("search objects: %w", err)
	}

	if len(searchResultItems) == 0 {
		return nil, "", ErrNodeNotFound
	}

	var searchResults = make([]prefixSearchResult, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return nil, "", fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = prefixSearchResult{
			ID:       item.ID,
			FilePath: item.Attributes[0],
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return nil, "", fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		psr.IsDeleteMarker = item.Attributes[2] != ""

		if item.Attributes[3] != "" {
			psr.DecryptedSize, err = strconv.ParseInt(item.Attributes[3], 10, 64)
			if err != nil {
				return nil, "", fmt.Errorf("invalid decrypted size %s: %w", item.Attributes[3], err)
			}
		}

		if item.Attributes[4] != "" {
			psr.PayloadSize, err = strconv.ParseInt(item.Attributes[4], 10, 64)
			if err != nil {
				return nil, "", fmt.Errorf("invalid payload size %s: %w", item.Attributes[4], err)
			}
		}

		if psr.DecryptedSize > 0 {
			psr.PayloadSize = psr.DecryptedSize
		}

		psr.PayloadChecksum = item.Attributes[5]

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b prefixSearchResult) int {
		if c := cmp.Compare(a.FilePath, b.FilePath); c != 0 { // direct order.
			return c
		}

		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	slices.SortFunc(searchResults, sortFunc)

	return searchResults, nextCursor, nil
}

func (n *layer) searchLatestVersionsByPrefix(ctx context.Context, bkt *data.BucketInfo, owner user.ID, prefix, cursor string, maxKeys int) ([]prefixSearchResult, string, error) {
	var (
		batch          = make(map[string]prefixSearchResult, maxKeys)
		searchedPage   []prefixSearchResult
		nextCursor     = cursor
		seachPageSize  = 1000
		err            error
		generateCursor bool

		// isBatchDone == true means we collected `maxKeys` objects to the response.
		isBatchDone bool
	)

	for len(batch) < maxKeys {
		searchedPage, nextCursor, err = n.searchAllVersionsInNeoFSByPrefix(ctx, bkt, owner, prefix, nextCursor, seachPageSize)
		if err != nil {
			if errors.Is(err, apistatus.ErrObjectAccessDenied) {
				return nil, "", s3errors.GetAPIError(s3errors.ErrAccessDenied)
			}

			return nil, "", fmt.Errorf("get all versions by prefix: %w", err)
		}

		for _, pageItem := range searchedPage {
			batchItem, ok := batch[pageItem.FilePath]
			if ok {
				// Store only the newest item.
				if pageItem.isNewerThan(batchItem) {
					batch[pageItem.FilePath] = pageItem
				}

				continue
			}

			// We collect unique items to response.
			if !isBatchDone {
				batch[pageItem.FilePath] = pageItem
				isBatchDone = len(batch) == maxKeys
			} else {
				// We already collected `maxKeys` objects. Despite it, current page has items for the next request.
				// We must shift cursor to the end of the current batch.
				generateCursor = true
			}
		}

		if len(nextCursor) == 0 {
			break
		}
	}

	// There are more items to search. We should look into the next page. It may contain objects from current batch.
	if len(nextCursor) != 0 {
		// It is possible we have to take more than the one extra pages. But as minimum one must be checked.
		var oneMorePage = true
		for oneMorePage {
			oneMorePage = false

			searchedPage, nextCursor, err = n.searchAllVersionsInNeoFSByPrefix(ctx, bkt, owner, prefix, nextCursor, seachPageSize)
			if err != nil {
				if errors.Is(err, apistatus.ErrObjectAccessDenied) {
					return nil, "", s3errors.GetAPIError(s3errors.ErrAccessDenied)
				}

				return nil, "", fmt.Errorf("get all versions by prefix: %w", err)
			}

			// searchedPage sorted by object.AttributeFilePath. If the last element from the extra page is presented in
			// current bath we should check another page in advice to find all versions of objects.
			if l := len(searchedPage); l > 0 {
				_, oneMorePage = batch[searchedPage[l-1].FilePath]
			}

			for _, result := range searchedPage {
				existing, ok := batch[result.FilePath]

				// We don't need new items which out of current batch.
				if !ok {
					// But it means there are not covered items and they must be retrieved in the next request.
					generateCursor = true
					continue
				}

				// Try to get the latest version of the object from this page.
				if result.isNewerThan(existing) {
					batch[result.FilePath] = result
				}
			}
		}
	}

	items := slices.Collect(maps.Values(batch))
	sortFunc := func(a, b prefixSearchResult) int {
		return cmp.Compare(a.FilePath, b.FilePath)
	}

	slices.SortFunc(items, sortFunc)

	// We did some manipulations with pages, we must to send to the client actual point to start from the next request.
	if len(nextCursor) != 0 || generateCursor {
		nextCursor = generateContinuationToken(items[len(items)-1].FilePath)
	}

	return items, nextCursor, nil
}

// objectDelete puts tombstone object into neofs.
func (n *layer) objectDelete(ctx context.Context, bktInfo *data.BucketInfo, idObj oid.ID) error {
	prm := PrmObjectDelete{
		Container: bktInfo.CID,
		Object:    idObj,
	}

	n.prepareAuthParameters(ctx, &prm.PrmAuth, bktInfo.Owner)

	n.cache.DeleteObject(oid.NewAddress(bktInfo.CID, idObj))

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

	if p.Marker != "" {
		filePath, err := url.PathUnescape(p.Marker)
		if err != nil {
			return nil, s3errors.GetAPIError(s3errors.ErrInvalidArgument)
		}

		prm.ContinuationToken = generateContinuationToken(filePath)
	}

	objects, next, err := n.getLatestObjectsVersions(ctx, prm)
	if err != nil {
		return nil, err
	}

	if next != "" {
		result.IsTruncated = true
		result.NextMarker, err = extractFilePath(next)
		if err != nil {
			return nil, err
		}
	}

	result.Prefixes, result.Objects = triageObjects(objects)

	return &result, nil
}

func generateContinuationToken(filePath string) string {
	var id oid.ID
	for i := range id {
		id[i] = 255
	}

	cursorBuf := bytes.NewBuffer(nil)
	cursorBuf.Write([]byte(object.AttributeFilePath))
	cursorBuf.WriteByte(0x00)
	cursorBuf.Write([]byte(filePath))
	cursorBuf.WriteByte(0x00)
	cursorBuf.Write(id[:])

	return base64.StdEncoding.EncodeToString(cursorBuf.Bytes())
}

func extractFilePath(continuationToken string) (string, error) {
	nextMarker, err := base64.StdEncoding.DecodeString(continuationToken)
	if err != nil {
		return "", err
	}

	parts := bytes.SplitN(nextMarker, []byte{0x00}, 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid marker, expected 2 parts, got %d", len(parts))
	}

	filePath := parts[1][0 : len(parts[1])-oid.Size]
	return string(filePath), nil
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

	if prm.ContinuationToken == "" && prm.Marker != "" {
		prm.ContinuationToken = generateContinuationToken(prm.Marker)
	}

	objects, next, err := n.getLatestObjectsVersions(ctx, prm)
	if err != nil {
		return nil, err
	}

	if next != "" {
		result.IsTruncated = true
		result.NextContinuationToken = next
	}

	result.Prefixes, result.Objects = triageObjects(objects)

	return &result, nil
}

func (n *layer) getLatestObjectsVersions(ctx context.Context, p allObjectParams) (objects []data.ObjectListResponseContent, next string, err error) {
	if p.MaxKeys == 0 {
		return nil, "", nil
	}

	owner := n.Owner(ctx)
	cacheKey := cache.CreateObjectsListCacheKey(p.Bucket.CID, p.Prefix, true)
	nodeVersions := n.cache.GetList(owner, cacheKey)

	var latestVersions []prefixSearchResult

	if nodeVersions == nil {
		latestVersions, next, err = n.searchLatestVersionsByPrefix(ctx, p.Bucket, p.Bucket.Owner, p.Prefix, p.ContinuationToken, p.MaxKeys)
		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return nil, "", nil
			}

			return nil, "", err
		}
	}

	if len(latestVersions) == 0 {
		return nil, "", nil
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
			oi = &data.ObjectListResponseContent{
				ID:      ver.ID,
				Owner:   p.Bucket.Owner,
				Created: time.Unix(ver.CreationTimestamp, 0),
				Name:    ver.FilePath,
				Size:    ver.PayloadSize,
				HashSum: ver.PayloadChecksum,
			}
		} else {
			oi.ID = ver.ID
		}

		objects = append(objects, *oi)
	}

	slices.SortFunc(objects, func(a, b data.ObjectListResponseContent) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return
}

func (n *layer) getAllObjectsVersions(ctx context.Context, bkt *data.BucketInfo, prefix, delimiter string) (map[string][]*data.ExtendedObjectInfo, error) {
	searchResults, err := n.searchAllVersionsInNeoFS(ctx, bkt, bkt.Owner, prefix, false)
	if err != nil {
		return nil, err
	}

	versions := make(map[string][]*data.ExtendedObjectInfo, len(searchResults))

	for _, ver := range searchResults {
		oi := &data.ObjectInfo{}

		if ver.IsDeleteMarker {
			oi.ID = ver.ID
			oi.Name = ver.FilePath
			oi.Size = ver.PayloadSize
			oi.Owner = bkt.Owner
			oi.Created = time.Unix(ver.CreationTimestamp, 0)
			oi.IsDeleteMarker = true
		} else {
			nv := data.NodeVersion{
				OID:      ver.ID,
				FilePath: prefix,
			}

			nv.IsUnversioned = !ver.IsVersioned

			if oi = n.objectInfoFromObjectsCacheOrNeoFS(ctx, bkt, &nv, prefix, delimiter); oi == nil {
				continue
			}
		}

		eoi := &data.ExtendedObjectInfo{
			ObjectInfo: oi,
			NodeVersion: &data.NodeVersion{
				OID:            oi.ID,
				Timestamp:      uint64(oi.Created.Unix()),
				ETag:           "",
				FilePath:       oi.Name,
				IsUnversioned:  !ver.IsVersioned,
				IsDeleteMarker: oi.IsDeleteMarker,
			},
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
	return ok || strings.HasPrefix(key, s3headers.NeoFSSystemMetadataPrefix)
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
	if extInfo := n.cache.GetObject(owner, oid.NewAddress(bktInfo.CID, node.OID)); extInfo != nil {
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
		IsDeleteMarker: node.IsDeleteMarker,
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

func (n *layer) searchBucketMetaObjects(ctx context.Context, bktInfo *data.BucketInfo, objType string) (oid.ID, error) {
	var (
		opts                client.SearchObjectsOptions
		owner               = n.Owner(ctx)
		filters             = make(object.SearchFilters, 0, 2)
		returningAttributes = []string{
			s3headers.MetaType,
			object.AttributeTimestamp,
		}
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil && bt.Issuer() == bktInfo.Owner {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(s3headers.MetaType, objType, object.MatchStringEqual)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bktInfo.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return oid.ID{}, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return oid.ID{}, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		return oid.ID{}, nil
	}

	var searchResults = make([]baseSearchResult, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		if len(item.Attributes) != len(returningAttributes) {
			return oid.ID{}, fmt.Errorf("invalid attribute count returned, expected %d, got %d", len(returningAttributes), len(item.Attributes))
		}

		var psr = baseSearchResult{
			ID: item.ID,
		}

		if item.Attributes[1] != "" {
			psr.CreationTimestamp, err = strconv.ParseInt(item.Attributes[1], 10, 64)
			if err != nil {
				return oid.ID{}, fmt.Errorf("invalid creation timestamp %s: %w", item.Attributes[1], err)
			}
		}

		searchResults = append(searchResults, psr)
	}

	sortFunc := func(a, b baseSearchResult) int {
		if c := cmp.Compare(b.CreationTimestamp, a.CreationTimestamp); c != 0 { // reverse order.
			return c
		}

		// It is a temporary decision. We can't figure out what object was first and what the second right now.
		return bytes.Compare(b.ID[:], a.ID[:]) // reverse order.
	}

	slices.SortFunc(searchResults, sortFunc)

	return searchResults[0].ID, nil
}

func extractLockDataFromAttrubute(lsr *locksSearchResult, attributeValue string) error {
	fields := make(map[string]string)
	if err := json.Unmarshal([]byte(attributeValue), &fields); err != nil {
		return fmt.Errorf("unmarshal lock meta fields: %w", err)
	}

	lsr.IsComplianceMode = fields[s3headers.FieldComplianceMode] == "true"

	if fields[s3headers.FieldRetentionUntilMode] != "" {
		ts, err := strconv.ParseInt(fields[s3headers.FieldRetentionUntilMode], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid retention until time: %w", err)
		}

		lsr.RetentionUntilMode = time.Unix(ts, 0).UTC()
	}

	return nil
}

// DeleteObjectMetaFiles removes all metafiles for.
func (n *layer) DeleteObjectMetaFiles(ctx context.Context, p *ObjectVersion) error {
	fs := make(object.SearchFilters, 0, 4)
	fs.AddFilter(object.AttributeFilePath, p.ObjectName, object.MatchStringEqual)
	fs.AddFilter(s3headers.MetaType, "", object.MatchStringNotEqual)
	fs.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)
	if p.VersionID != "" {
		fs.AddFilter(s3headers.AttributeObjectVersion, p.VersionID, object.MatchStringEqual)
	}

	var opts client.SearchObjectsOptions
	if bt := bearerTokenFromContext(ctx, p.BktInfo.Owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	res, err := n.neoFS.SearchObjectsV2(ctx, p.BktInfo.CID, fs, nil, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return fmt.Errorf("search object version: %w", err)
	}

	if len(res) == 0 {
		return nil
	}

	for i := range res {
		if err = n.objectDelete(ctx, p.BktInfo, res[i].ID); err != nil {
			// only log.
			n.log.Warn("couldn't delete meta object", zap.Stringer("oid", res[i].ID), zap.Stringer("cid", p.BktInfo.CID), zap.Error(err))
		}
	}

	n.cache.DeleteTagging(objectTaggingCacheKey(p))

	return nil
}

// searchEverythingForRemove returns all object versions and metadata files related to objectName.
//
// Returns ErrNodeNotFound if zero objects found.
func (n *layer) searchEverythingForRemove(ctx context.Context, bkt *data.BucketInfo, owner user.ID, objectName string, onlyUnversioned bool) ([]oid.ID, error) {
	var (
		filters             = make(object.SearchFilters, 0, 3)
		returningAttributes = []string{
			object.AttributeFilePath,
		}

		opts client.SearchObjectsOptions
	)

	if bt := bearerTokenFromContext(ctx, owner); bt != nil {
		opts.WithBearerToken(*bt)
	}

	filters.AddFilter(object.AttributeFilePath, objectName, object.MatchStringEqual)
	filters.AddTypeFilter(object.MatchStringEqual, object.TypeRegular)

	if onlyUnversioned {
		filters.AddFilter(s3headers.AttributeVersioningState, "", object.MatchNotPresent)
	}

	searchResultItems, err := n.neoFS.SearchObjectsV2(ctx, bkt.CID, filters, returningAttributes, opts)
	if err != nil {
		if errors.Is(err, apistatus.ErrObjectAccessDenied) {
			return nil, s3errors.GetAPIError(s3errors.ErrAccessDenied)
		}

		return nil, fmt.Errorf("search object version: %w", err)
	}

	if len(searchResultItems) == 0 {
		return nil, ErrNodeNotFound
	}

	var oids = make([]oid.ID, 0, len(searchResultItems))

	for _, item := range searchResultItems {
		oids = append(oids, item.ID)
	}

	return oids, nil
}
