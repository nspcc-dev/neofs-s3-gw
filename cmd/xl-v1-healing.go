/*
 * MinIO Cloud Storage, (C) 2016, 2017, 2018 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/madmin"
	"github.com/minio/minio/pkg/sync/errgroup"
)

func (xl xlObjects) ReloadFormat(ctx context.Context, dryRun bool) error {
	logger.LogIf(ctx, NotImplemented{})
	return NotImplemented{}
}

func (xl xlObjects) HealFormat(ctx context.Context, dryRun bool) (madmin.HealResultItem, error) {
	logger.LogIf(ctx, NotImplemented{})
	return madmin.HealResultItem{}, NotImplemented{}
}

// Heals a bucket if it doesn't exist on one of the disks, additionally
// also heals the missing entries for bucket metadata files
// `policy.json, notification.xml, listeners.json`.
func (xl xlObjects) HealBucket(ctx context.Context, bucket string, dryRun, remove bool) (
	result madmin.HealResultItem, err error) {
	if !dryRun {
		defer ObjectPathUpdated(bucket)
	}

	storageDisks := xl.getDisks()
	storageEndpoints := xl.getEndpoints()

	// get write quorum for an object
	writeQuorum := getWriteQuorum(len(storageDisks))

	// Heal bucket.
	return healBucket(ctx, storageDisks, storageEndpoints, bucket, writeQuorum, dryRun)
}

// Heal bucket - create buckets on disks where it does not exist.
func healBucket(ctx context.Context, storageDisks []StorageAPI, storageEndpoints []string, bucket string, writeQuorum int,
	dryRun bool) (res madmin.HealResultItem, err error) {

	// Initialize sync waitgroup.
	g := errgroup.WithNErrs(len(storageDisks))

	// Disk states slices
	beforeState := make([]string, len(storageDisks))
	afterState := make([]string, len(storageDisks))

	// Make a volume entry on all underlying storage disks.
	for index := range storageDisks {
		index := index
		g.Go(func() error {
			if storageDisks[index] == nil {
				beforeState[index] = madmin.DriveStateOffline
				afterState[index] = madmin.DriveStateOffline
				return errDiskNotFound
			}
			if _, serr := storageDisks[index].StatVol(bucket); serr != nil {
				if serr == errDiskNotFound {
					beforeState[index] = madmin.DriveStateOffline
					afterState[index] = madmin.DriveStateOffline
					return serr
				}
				if serr != errVolumeNotFound {
					beforeState[index] = madmin.DriveStateCorrupt
					afterState[index] = madmin.DriveStateCorrupt
					return serr
				}

				beforeState[index] = madmin.DriveStateMissing
				afterState[index] = madmin.DriveStateMissing

				// mutate only if not a dry-run
				if dryRun {
					return nil
				}

				return serr
			}
			beforeState[index] = madmin.DriveStateOk
			afterState[index] = madmin.DriveStateOk
			return nil
		}, index)
	}

	errs := g.Wait()

	reducedErr := reduceWriteQuorumErrs(ctx, errs, bucketOpIgnoredErrs, writeQuorum-1)
	if reducedErr == errVolumeNotFound {
		return res, nil
	}

	// Initialize heal result info
	res = madmin.HealResultItem{
		Type:      madmin.HealItemBucket,
		Bucket:    bucket,
		DiskCount: len(storageDisks),
	}

	for i := range beforeState {
		res.Before.Drives = append(res.Before.Drives, madmin.HealDriveInfo{
			UUID:     "",
			Endpoint: storageEndpoints[i],
			State:    beforeState[i],
		})
	}

	// Initialize sync waitgroup.
	g = errgroup.WithNErrs(len(storageDisks))

	// Make a volume entry on all underlying storage disks.
	for index := range storageDisks {
		index := index
		g.Go(func() error {
			if beforeState[index] == madmin.DriveStateMissing {
				makeErr := storageDisks[index].MakeVol(bucket)
				if makeErr == nil {
					afterState[index] = madmin.DriveStateOk
				}
				return makeErr
			}
			return errs[index]
		}, index)
	}

	errs = g.Wait()

	reducedErr = reduceWriteQuorumErrs(ctx, errs, bucketOpIgnoredErrs, writeQuorum)
	if reducedErr != nil {
		return res, reducedErr
	}

	for i := range afterState {
		res.After.Drives = append(res.After.Drives, madmin.HealDriveInfo{
			UUID:     "",
			Endpoint: storageEndpoints[i],
			State:    afterState[i],
		})
	}

	return res, nil
}

// listAllBuckets lists all buckets from all disks. It also
// returns the occurrence of each buckets in all disks
func listAllBuckets(storageDisks []StorageAPI, healBuckets map[string]VolInfo) (err error) {
	for _, disk := range storageDisks {
		if disk == nil {
			continue
		}
		var volsInfo []VolInfo
		volsInfo, err = disk.ListVols()
		if err != nil {
			if IsErrIgnored(err, bucketMetadataOpIgnoredErrs...) {
				continue
			}
			return err
		}
		for _, volInfo := range volsInfo {
			// StorageAPI can send volume names which are
			// incompatible with buckets - these are
			// skipped, like the meta-bucket.
			if isReservedOrInvalidBucket(volInfo.Name, false) {
				continue
			}
			// always save unique buckets across drives.
			if _, ok := healBuckets[volInfo.Name]; !ok {
				healBuckets[volInfo.Name] = volInfo
			}

		}
	}
	return nil
}

// Only heal on disks where we are sure that healing is needed. We can expand
// this list as and when we figure out more errors can be added to this list safely.
func shouldHealObjectOnDisk(xlErr, dataErr error, meta xlMetaV1, quorumModTime time.Time) bool {
	switch xlErr {
	case errFileNotFound:
		return true
	case errCorruptedFormat:
		return true
	}
	if xlErr == nil {
		// If xl.json was read fine but there may be problem with the part.N files.
		if IsErr(dataErr, []error{
			errFileNotFound,
			errFileCorrupt,
		}...) {
			return true
		}
		if !quorumModTime.Equal(meta.Stat.ModTime) {
			return true
		}
	}
	return false
}

// Heals an object by re-writing corrupt/missing erasure blocks.
func (xl xlObjects) healObject(ctx context.Context, bucket string, object string,
	partsMetadata []xlMetaV1, errs []error, latestXLMeta xlMetaV1,
	dryRun bool, remove bool, scanMode madmin.HealScanMode) (result madmin.HealResultItem, err error) {

	dataBlocks := latestXLMeta.Erasure.DataBlocks

	storageDisks := xl.getDisks()
	storageEndpoints := xl.getEndpoints()

	// List of disks having latest version of the object xl.json
	// (by modtime).
	latestDisks, modTime := listOnlineDisks(storageDisks, partsMetadata, errs)

	// List of disks having all parts as per latest xl.json.
	availableDisks, dataErrs := disksWithAllParts(ctx, latestDisks, partsMetadata, errs, bucket, object, scanMode)

	// Initialize heal result object
	result = madmin.HealResultItem{
		Type:         madmin.HealItemObject,
		Bucket:       bucket,
		Object:       object,
		DiskCount:    len(storageDisks),
		ParityBlocks: latestXLMeta.Erasure.ParityBlocks,
		DataBlocks:   latestXLMeta.Erasure.DataBlocks,

		// Initialize object size to -1, so we can detect if we are
		// unable to reliably find the object size.
		ObjectSize: -1,
	}

	// Loop to find number of disks with valid data, per-drive
	// data state and a list of outdated disks on which data needs
	// to be healed.
	outDatedDisks := make([]StorageAPI, len(storageDisks))
	numAvailableDisks := 0
	disksToHealCount := 0
	for i, v := range availableDisks {
		driveState := ""
		switch {
		case v != nil:
			driveState = madmin.DriveStateOk
			numAvailableDisks++
			// If data is sane on any one disk, we can
			// extract the correct object size.
			result.ObjectSize = partsMetadata[i].Stat.Size
			result.ParityBlocks = partsMetadata[i].Erasure.ParityBlocks
			result.DataBlocks = partsMetadata[i].Erasure.DataBlocks
		case errs[i] == errDiskNotFound, dataErrs[i] == errDiskNotFound:
			driveState = madmin.DriveStateOffline
		case errs[i] == errFileNotFound, errs[i] == errVolumeNotFound:
			fallthrough
		case dataErrs[i] == errFileNotFound, dataErrs[i] == errVolumeNotFound:
			driveState = madmin.DriveStateMissing
		default:
			// all remaining cases imply corrupt data/metadata
			driveState = madmin.DriveStateCorrupt
		}

		if shouldHealObjectOnDisk(errs[i], dataErrs[i], partsMetadata[i], modTime) {
			outDatedDisks[i] = storageDisks[i]
			disksToHealCount++
			result.Before.Drives = append(result.Before.Drives, madmin.HealDriveInfo{
				UUID:     "",
				Endpoint: storageEndpoints[i],
				State:    driveState,
			})
			result.After.Drives = append(result.After.Drives, madmin.HealDriveInfo{
				UUID:     "",
				Endpoint: storageEndpoints[i],
				State:    driveState,
			})
			continue
		}
		result.Before.Drives = append(result.Before.Drives, madmin.HealDriveInfo{
			UUID:     "",
			Endpoint: storageEndpoints[i],
			State:    driveState,
		})
		result.After.Drives = append(result.After.Drives, madmin.HealDriveInfo{
			UUID:     "",
			Endpoint: storageEndpoints[i],
			State:    driveState,
		})
	}

	// If less than read quorum number of disks have all the parts
	// of the data, we can't reconstruct the erasure-coded data.
	if numAvailableDisks < dataBlocks {
		// Check if xl.json, and corresponding parts are also missing.
		if m, ok := isObjectDangling(partsMetadata, errs, dataErrs); ok {
			writeQuorum := m.Erasure.DataBlocks + 1
			if m.Erasure.DataBlocks == 0 {
				writeQuorum = getWriteQuorum(len(storageDisks))
			}
			if !dryRun && remove {
				err = xl.deleteObject(ctx, bucket, object, writeQuorum, false)
			}
			return defaultHealResult(latestXLMeta, storageDisks, storageEndpoints, errs, bucket, object), err
		}
		return result, toObjectErr(errXLReadQuorum, bucket, object)
	}

	if disksToHealCount == 0 {
		// Nothing to heal!
		return result, nil
	}

	// After this point, only have to repair data on disk - so
	// return if it is a dry-run
	if dryRun {
		return result, nil
	}

	// Latest xlMetaV1 for reference. If a valid metadata is not
	// present, it is as good as object not found.
	latestMeta, pErr := pickValidXLMeta(ctx, partsMetadata, modTime, dataBlocks)
	if pErr != nil {
		return result, toObjectErr(pErr, bucket, object)
	}

	// Clear data files of the object on outdated disks
	for _, disk := range outDatedDisks {
		// Before healing outdated disks, we need to remove
		// xl.json and part files from "bucket/object/" so
		// that rename(minioMetaBucket, "tmp/tmpuuid/",
		// "bucket", "object/") succeeds.
		if disk == nil {
			// Not an outdated disk.
			continue
		}

		// List and delete the object directory,
		files, derr := disk.ListDir(bucket, object, -1, "")
		if derr == nil {
			for _, entry := range files {
				_ = disk.DeleteFile(bucket,
					pathJoin(object, entry))
			}
		}
	}

	// Reorder so that we have data disks first and parity disks next.
	latestDisks = shuffleDisks(availableDisks, latestMeta.Erasure.Distribution)
	outDatedDisks = shuffleDisks(outDatedDisks, latestMeta.Erasure.Distribution)
	partsMetadata = shufflePartsMetadata(partsMetadata, latestMeta.Erasure.Distribution)
	for i := range outDatedDisks {
		if outDatedDisks[i] == nil {
			continue
		}
		partsMetadata[i] = newXLMetaFromXLMeta(latestMeta)
	}

	// We write at temporary location and then rename to final location.
	tmpID := mustGetUUID()

	// Heal each part. erasureHealFile() will write the healed
	// part to .minio/tmp/uuid/ which needs to be renamed later to
	// the final location.
	erasure, err := NewErasure(ctx, latestMeta.Erasure.DataBlocks,
		latestMeta.Erasure.ParityBlocks, latestMeta.Erasure.BlockSize)
	if err != nil {
		return result, toObjectErr(err, bucket, object)
	}

	erasureInfo := latestMeta.Erasure
	for partIndex := 0; partIndex < len(latestMeta.Parts); partIndex++ {
		partSize := latestMeta.Parts[partIndex].Size
		partActualSize := latestMeta.Parts[partIndex].ActualSize
		partNumber := latestMeta.Parts[partIndex].Number
		tillOffset := erasure.ShardFileTillOffset(0, partSize, partSize)
		readers := make([]io.ReaderAt, len(latestDisks))
		checksumAlgo := erasureInfo.GetChecksumInfo(partNumber).Algorithm
		for i, disk := range latestDisks {
			if disk == OfflineDisk {
				continue
			}
			checksumInfo := partsMetadata[i].Erasure.GetChecksumInfo(partNumber)
			partPath := pathJoin(object, fmt.Sprintf("part.%d", partNumber))
			readers[i] = newBitrotReader(disk, bucket, partPath, tillOffset, checksumAlgo, checksumInfo.Hash, erasure.ShardSize())
		}
		writers := make([]io.Writer, len(outDatedDisks))
		for i, disk := range outDatedDisks {
			if disk == OfflineDisk {
				continue
			}
			partPath := pathJoin(tmpID, fmt.Sprintf("part.%d", partNumber))
			writers[i] = newBitrotWriter(disk, minioMetaTmpBucket, partPath, tillOffset, checksumAlgo, erasure.ShardSize())
		}
		hErr := erasure.Heal(ctx, readers, writers, partSize)
		closeBitrotReaders(readers)
		closeBitrotWriters(writers)
		if hErr != nil {
			return result, toObjectErr(hErr, bucket, object)
		}
		// outDatedDisks that had write errors should not be
		// written to for remaining parts, so we nil it out.
		for i, disk := range outDatedDisks {
			if disk == nil {
				continue
			}
			// A non-nil stale disk which did not receive
			// a healed part checksum had a write error.
			if writers[i] == nil {
				outDatedDisks[i] = nil
				disksToHealCount--
				continue
			}
			partsMetadata[i].AddObjectPart(partNumber, "", partSize, partActualSize)
			partsMetadata[i].Erasure.AddChecksumInfo(ChecksumInfo{
				PartNumber: partNumber,
				Algorithm:  checksumAlgo,
				Hash:       bitrotWriterSum(writers[i]),
			})
		}

		// If all disks are having errors, we give up.
		if disksToHealCount == 0 {
			return result, fmt.Errorf("all disks without up-to-date data had write errors")
		}
	}

	// Cleanup in case of xl.json writing failure
	writeQuorum := latestMeta.Erasure.DataBlocks + 1
	defer xl.deleteObject(ctx, minioMetaTmpBucket, tmpID, writeQuorum, false)

	// Generate and write `xl.json` generated from other disks.
	outDatedDisks, aErr := writeUniqueXLMetadata(ctx, outDatedDisks, minioMetaTmpBucket, tmpID,
		partsMetadata, diskCount(outDatedDisks))
	if aErr != nil {
		return result, toObjectErr(aErr, bucket, object)
	}

	// Rename from tmp location to the actual location.
	for _, disk := range outDatedDisks {
		if disk == nil {
			continue
		}

		// Attempt a rename now from healed data to final location.
		aErr = disk.RenameFile(minioMetaTmpBucket, retainSlash(tmpID), bucket,
			retainSlash(object))
		if aErr != nil {
			logger.LogIf(ctx, aErr)
			return result, toObjectErr(aErr, bucket, object)
		}

		for i, v := range result.Before.Drives {
			if v.Endpoint == disk.String() {
				result.After.Drives[i].State = madmin.DriveStateOk
			}
		}
	}

	// Set the size of the object in the heal result
	result.ObjectSize = latestMeta.Stat.Size

	return result, nil
}

// healObjectDir - heals object directory specifically, this special call
// is needed since we do not have a special backend format for directories.
func (xl xlObjects) healObjectDir(ctx context.Context, bucket, object string, dryRun bool, remove bool) (hr madmin.HealResultItem, err error) {
	storageDisks := xl.getDisks()
	storageEndpoints := xl.getEndpoints()

	// Initialize heal result object
	hr = madmin.HealResultItem{
		Type:         madmin.HealItemObject,
		Bucket:       bucket,
		Object:       object,
		DiskCount:    len(storageDisks),
		ParityBlocks: getDefaultParityBlocks(len(storageDisks)),
		DataBlocks:   getDefaultDataBlocks(len(storageDisks)),
		ObjectSize:   0,
	}

	hr.Before.Drives = make([]madmin.HealDriveInfo, len(storageDisks))
	hr.After.Drives = make([]madmin.HealDriveInfo, len(storageDisks))

	errs := statAllDirs(ctx, storageDisks, bucket, object)
	danglingObject := isObjectDirDangling(errs)
	if danglingObject {
		if !dryRun && remove {
			xl.deleteObject(ctx, bucket, object, hr.DataBlocks+1, true)
		}
	}

	// Prepare object creation in all disks
	for i, err := range errs {
		drive := storageEndpoints[i]
		switch err {
		case nil:
			hr.Before.Drives[i] = madmin.HealDriveInfo{Endpoint: drive, State: madmin.DriveStateOk}
			hr.After.Drives[i] = madmin.HealDriveInfo{Endpoint: drive, State: madmin.DriveStateOk}
		case errDiskNotFound:
			hr.Before.Drives[i] = madmin.HealDriveInfo{State: madmin.DriveStateOffline}
			hr.After.Drives[i] = madmin.HealDriveInfo{State: madmin.DriveStateOffline}
		case errVolumeNotFound, errFileNotFound:
			// Bucket or prefix/directory not found
			hr.Before.Drives[i] = madmin.HealDriveInfo{Endpoint: drive, State: madmin.DriveStateMissing}
			hr.After.Drives[i] = madmin.HealDriveInfo{Endpoint: drive, State: madmin.DriveStateMissing}
		default:
			hr.Before.Drives[i] = madmin.HealDriveInfo{Endpoint: drive, State: madmin.DriveStateCorrupt}
			hr.After.Drives[i] = madmin.HealDriveInfo{Endpoint: drive, State: madmin.DriveStateCorrupt}
		}
	}
	if dryRun || danglingObject {
		return hr, nil
	}
	for i, err := range errs {
		if err == errVolumeNotFound || err == errFileNotFound {
			// Bucket or prefix/directory not found
			merr := storageDisks[i].MakeVol(pathJoin(bucket, object))
			switch merr {
			case nil, errVolumeExists:
				hr.After.Drives[i].State = madmin.DriveStateOk
			case errDiskNotFound:
				hr.After.Drives[i].State = madmin.DriveStateOffline
			default:
				logger.LogIf(ctx, merr)
				hr.After.Drives[i].State = madmin.DriveStateCorrupt
			}
		}
	}
	return hr, nil
}

// Populates default heal result item entries with possible values when we are returning prematurely.
// This is to ensure that in any circumstance we are not returning empty arrays with wrong values.
func defaultHealResult(latestXLMeta xlMetaV1, storageDisks []StorageAPI, storageEndpoints []string, errs []error, bucket, object string) madmin.HealResultItem {
	// Initialize heal result object
	result := madmin.HealResultItem{
		Type:      madmin.HealItemObject,
		Bucket:    bucket,
		Object:    object,
		DiskCount: len(storageDisks),

		// Initialize object size to -1, so we can detect if we are
		// unable to reliably find the object size.
		ObjectSize: -1,
	}
	if latestXLMeta.IsValid() {
		result.ObjectSize = latestXLMeta.Stat.Size
	}

	for index, disk := range storageDisks {
		if disk == nil {
			result.Before.Drives = append(result.Before.Drives, madmin.HealDriveInfo{
				UUID:     "",
				Endpoint: storageEndpoints[index],
				State:    madmin.DriveStateOffline,
			})
			result.After.Drives = append(result.After.Drives, madmin.HealDriveInfo{
				UUID:     "",
				Endpoint: storageEndpoints[index],
				State:    madmin.DriveStateOffline,
			})
			continue
		}
		driveState := madmin.DriveStateCorrupt
		switch errs[index] {
		case errFileNotFound, errVolumeNotFound:
			driveState = madmin.DriveStateMissing
		}
		result.Before.Drives = append(result.Before.Drives, madmin.HealDriveInfo{
			UUID:     "",
			Endpoint: storageEndpoints[index],
			State:    driveState,
		})
		result.After.Drives = append(result.After.Drives, madmin.HealDriveInfo{
			UUID:     "",
			Endpoint: storageEndpoints[index],
			State:    driveState,
		})
	}

	if !latestXLMeta.IsValid() {
		// Default to most common configuration for erasure blocks.
		result.ParityBlocks = getDefaultParityBlocks(len(storageDisks))
		result.DataBlocks = getDefaultDataBlocks(len(storageDisks))
	} else {
		result.ParityBlocks = latestXLMeta.Erasure.ParityBlocks
		result.DataBlocks = latestXLMeta.Erasure.DataBlocks
	}

	return result
}

// Stat all directories.
func statAllDirs(ctx context.Context, storageDisks []StorageAPI, bucket, prefix string) []error {
	g := errgroup.WithNErrs(len(storageDisks))
	for index, disk := range storageDisks {
		if disk == nil {
			continue
		}
		index := index
		g.Go(func() error {
			entries, err := storageDisks[index].ListDir(bucket, prefix, 1, "")
			if err != nil {
				return err
			}
			if len(entries) > 0 {
				return errVolumeNotEmpty
			}
			return nil
		}, index)
	}

	return g.Wait()
}

// ObjectDir is considered dangling/corrupted if any only
// if total disks - a combination of corrupted and missing
// files is lesser than N/2+1 number of disks.
func isObjectDirDangling(errs []error) (ok bool) {
	var found int
	var notFound int
	var foundNotEmpty int
	var otherFound int
	for _, readErr := range errs {
		if readErr == nil {
			found++
		} else if readErr == errFileNotFound || readErr == errVolumeNotFound {
			notFound++
		} else if readErr == errVolumeNotEmpty {
			foundNotEmpty++
		} else {
			otherFound++
		}
	}
	return found+foundNotEmpty+otherFound < notFound
}

// Object is considered dangling/corrupted if any only
// if total disks - a combination of corrupted and missing
// files is lesser than number of data blocks.
func isObjectDangling(metaArr []xlMetaV1, errs []error, dataErrs []error) (validMeta xlMetaV1, ok bool) {
	// We can consider an object data not reliable
	// when xl.json is not found in read quorum disks.
	// or when xl.json is not readable in read quorum disks.
	var notFoundXLJSON, corruptedXLJSON int
	for _, readErr := range errs {
		if readErr == errFileNotFound {
			notFoundXLJSON++
		} else if readErr == errCorruptedFormat {
			corruptedXLJSON++
		}
	}
	var notFoundParts int
	for i := range dataErrs {
		// Only count part errors, if the error is not
		// same as xl.json error. This is to avoid
		// double counting when both parts and xl.json
		// are not available.
		if errs[i] != dataErrs[i] {
			if dataErrs[i] == errFileNotFound {
				notFoundParts++
			}
		}
	}

	for _, m := range metaArr {
		if !m.IsValid() {
			continue
		}
		validMeta = m
		break
	}

	// We couldn't find any valid meta we are indeed corrupted, return true right away.
	if validMeta.Erasure.DataBlocks == 0 {
		return validMeta, true
	}

	// We have valid meta, now verify if we have enough files with parity blocks.
	return validMeta, corruptedXLJSON+notFoundXLJSON+notFoundParts > validMeta.Erasure.ParityBlocks
}

// HealObject - heal the given object, automatically deletes the object if stale/corrupted if `remove` is true.
func (xl xlObjects) HealObject(ctx context.Context, bucket, object string, opts madmin.HealOpts) (hr madmin.HealResultItem, err error) {
	// Create context that also contains information about the object and bucket.
	// The top level handler might not have this information.
	reqInfo := logger.GetReqInfo(ctx)
	var newReqInfo *logger.ReqInfo
	if reqInfo != nil {
		newReqInfo = logger.NewReqInfo(reqInfo.RemoteHost, reqInfo.UserAgent, reqInfo.DeploymentID, reqInfo.RequestID, reqInfo.API, bucket, object)
	} else {
		newReqInfo = logger.NewReqInfo("", "", globalDeploymentID, "", "Heal", bucket, object)
	}
	healCtx := logger.SetReqInfo(GlobalContext, newReqInfo)

	// Healing directories handle it separately.
	if HasSuffix(object, SlashSeparator) {
		return xl.healObjectDir(healCtx, bucket, object, opts.DryRun, opts.Remove)
	}

	storageDisks := xl.getDisks()
	storageEndpoints := xl.getEndpoints()

	// Read metadata files from all the disks
	partsMetadata, errs := readAllXLMetadata(healCtx, storageDisks, bucket, object)

	// Check if the object is dangling, if yes and user requested
	// remove we simply delete it from namespace.
	if m, ok := isObjectDangling(partsMetadata, errs, []error{}); ok {
		writeQuorum := m.Erasure.DataBlocks + 1
		if m.Erasure.DataBlocks == 0 {
			writeQuorum = getWriteQuorum(len(storageDisks))
		}
		if !opts.DryRun && opts.Remove {
			xl.deleteObject(healCtx, bucket, object, writeQuorum, false)
		}
		err = reduceReadQuorumErrs(ctx, errs, nil, writeQuorum-1)
		return defaultHealResult(xlMetaV1{}, storageDisks, storageEndpoints, errs, bucket, object), toObjectErr(err, bucket, object)
	}

	latestXLMeta, err := getLatestXLMeta(healCtx, partsMetadata, errs)
	if err != nil {
		return defaultHealResult(xlMetaV1{}, storageDisks, storageEndpoints, errs, bucket, object), toObjectErr(err, bucket, object)
	}

	errCount := 0
	for _, err := range errs {
		if err != nil {
			errCount++
		}
	}

	if errCount == len(errs) {
		// Only if we get errors from all the disks we return error. Else we need to
		// continue to return filled madmin.HealResultItem struct which includes info
		// on what disks the file is available etc.
		if err = reduceReadQuorumErrs(ctx, errs, nil, latestXLMeta.Erasure.DataBlocks); err != nil {
			if m, ok := isObjectDangling(partsMetadata, errs, []error{}); ok {
				writeQuorum := m.Erasure.DataBlocks + 1
				if m.Erasure.DataBlocks == 0 {
					writeQuorum = getWriteQuorum(len(storageDisks))
				}
				if !opts.DryRun && opts.Remove {
					xl.deleteObject(ctx, bucket, object, writeQuorum, false)
				}
			}
			return defaultHealResult(latestXLMeta, storageDisks, storageEndpoints, errs, bucket, object), toObjectErr(err, bucket, object)
		}
	}

	// Heal the object.
	return xl.healObject(healCtx, bucket, object, partsMetadata, errs, latestXLMeta, opts.DryRun, opts.Remove, opts.ScanMode)
}
