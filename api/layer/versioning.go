package layer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/nspcc-dev/neofs-s3-gw/api/data"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

func (n *layer) ListObjectVersions(ctx context.Context, p *ListObjectVersionsParams) (*ListObjectVersionsInfo, error) {
	var (
		allObjects      = make([]*data.ExtendedObjectInfo, 0, p.MaxKeys)
		res             = &ListObjectVersionsInfo{}
		cursor          string
		id              oid.ID
		keyMarkerLastTs uint64
		err             error
	)

	// We should start with specific key.
	if p.KeyMarker != "" {
		// We should start with specific key version.
		if p.VersionIDMarker != "" {
			parts := strings.Split(p.VersionIDMarker, ":")
			if err = id.DecodeString(parts[0]); err != nil {
				return nil, err
			}

			if len(parts) == 2 {
				f, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					return nil, err
				}

				keyMarkerLastTs = uint64(f)
			}
		}

		cursor = generateAdjustedContinuationToken(p.KeyMarker, oid.ID{})
	}

	for {
		versions, nextCursor, err := n.getAllObjectsVersions(ctx, p.BktInfo, p.Prefix, cursor, p.Delimiter)
		cursor = nextCursor

		if err != nil {
			if errors.Is(err, ErrNodeNotFound) {
				return res, nil
			}
			return nil, err
		}

		sortedNames := slices.Collect(maps.Keys(versions))
		slices.Sort(sortedNames)

		for _, name := range sortedNames {
			sortedVersions := versions[name]
			// The object with "null" version should be only one. We get only last (actual) one.
			var isNullVersionCounted bool
			var isLatestShouldBeSet = true

			for i, version := range sortedVersions {
				version.IsLatest = i == 0
				if version.NodeVersion.IsUnversioned && isNullVersionCounted {
					continue
				}

				if version.NodeVersion.IsUnversioned {
					isNullVersionCounted = true
				}

				// On the next pages, we should filter out objects we already showed on the previous page.
				if p.KeyMarker == version.NodeVersion.FilePath && keyMarkerLastTs > 0 {
					// Objects are sorted in reverse order. The most recently stored objects are at the beginning.
					// We should skip what has already been shown by time.
					if keyMarkerLastTs < version.NodeVersion.Timestamp {
						continue
					}

					// But sometimes the objects with the same name can be created in one second.
					// To handle this situation, we have to filter out processed objects with OIDs.
					if keyMarkerLastTs == version.NodeVersion.Timestamp && !id.IsZero() {
						if bytes.Compare(id[:], version.NodeVersion.OID[:]) < 0 {
							continue
						}
					}
				}

				if !version.IsLatest && isLatestShouldBeSet {
					version.IsLatest = true
				}

				isLatestShouldBeSet = false

				allObjects = append(allObjects, version)
			}
		}

		if nextCursor == "" || len(allObjects) >= p.MaxKeys {
			break
		}
	}

	res.CommonPrefixes, allObjects = triageExtendedObjects(allObjects)

	if len(allObjects) > p.MaxKeys {
		res.IsTruncated = true
		oi := allObjects[p.MaxKeys].ObjectInfo

		res.NextKeyMarker = oi.Name
		res.NextVersionIDMarker = fmt.Sprintf("%s:%d", oi.VersionID(), oi.Created.Unix())

		allObjects = allObjects[:p.MaxKeys]
		res.KeyMarker = allObjects[p.MaxKeys-1].ObjectInfo.Name
		res.VersionIDMarker = allObjects[p.MaxKeys-1].ObjectInfo.VersionID()
	}

	res.Version, res.DeleteMarker = triageVersions(allObjects)
	return res, nil
}

func triageVersions(objVersions []*data.ExtendedObjectInfo) ([]*data.ExtendedObjectInfo, []*data.ExtendedObjectInfo) {
	if len(objVersions) == 0 {
		return nil, nil
	}

	var resVersion []*data.ExtendedObjectInfo
	var resDelMarkVersions []*data.ExtendedObjectInfo

	for _, version := range objVersions {
		if version.NodeVersion.IsDeleteMarker {
			resDelMarkVersions = append(resDelMarkVersions, version)
		} else {
			resVersion = append(resVersion, version)
		}
	}

	return resVersion, resDelMarkVersions
}
