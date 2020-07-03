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
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/bpool"
	"github.com/minio/minio/pkg/color"
	"github.com/minio/minio/pkg/dsync"
	"github.com/minio/minio/pkg/madmin"
	"github.com/minio/minio/pkg/sync/errgroup"
)

// XL constants.
const (
	// XL metadata file carries per object metadata.
	xlMetaJSONFile = "xl.json"
)

// OfflineDisk represents an unavailable disk.
var OfflineDisk StorageAPI // zero value is nil

// partialOperation is a successful upload/delete
// of an object but not written in all disks (having quorum)
type partialOperation struct {
	bucket    string
	object    string
	failedSet int
}

// xlObjects - Implements XL object layer.
type xlObjects struct {
	GatewayUnsupported

	// getDisks returns list of storageAPIs.
	getDisks func() []StorageAPI

	// getLockers returns list of remote and local lockers.
	getLockers func() []dsync.NetLocker

	// getEndpoints returns list of endpoint strings belonging this set.
	// some may be local and some remote.
	getEndpoints func() []string

	// Locker mutex map.
	nsMutex *nsLockMap

	// Byte pools used for temporary i/o buffers.
	bp *bpool.BytePoolCap

	mrfOpCh chan partialOperation
}

// NewNSLock - initialize a new namespace RWLocker instance.
func (xl xlObjects) NewNSLock(ctx context.Context, bucket string, objects ...string) RWLocker {
	return xl.nsMutex.NewNSLock(ctx, xl.getLockers, bucket, objects...)
}

// Shutdown function for object storage interface.
func (xl xlObjects) Shutdown(ctx context.Context) error {
	// Add any object layer shutdown activities here.
	closeStorageDisks(xl.getDisks())
	return nil
}

// byDiskTotal is a collection satisfying sort.Interface.
type byDiskTotal []DiskInfo

func (d byDiskTotal) Len() int      { return len(d) }
func (d byDiskTotal) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d byDiskTotal) Less(i, j int) bool {
	return d[i].Total < d[j].Total
}

// getDisksInfo - fetch disks info across all other storage API.
func getDisksInfo(disks []StorageAPI, endpoints []string) (disksInfo []DiskInfo, errs []error, onlineDisks, offlineDisks madmin.BackendDisks) {
	disksInfo = make([]DiskInfo, len(disks))
	onlineDisks = make(madmin.BackendDisks)
	offlineDisks = make(madmin.BackendDisks)

	for _, ep := range endpoints {
		if _, ok := offlineDisks[ep]; !ok {
			offlineDisks[ep] = 0
		}
		if _, ok := onlineDisks[ep]; !ok {
			onlineDisks[ep] = 0
		}
	}

	g := errgroup.WithNErrs(len(disks))
	for index := range disks {
		index := index
		g.Go(func() error {
			if disks[index] == OfflineDisk {
				// Storage disk is empty, perhaps ignored disk or not available.
				return errDiskNotFound
			}
			info, err := disks[index].DiskInfo()
			if err != nil {
				if !IsErr(err, baseErrs...) {
					reqInfo := (&logger.ReqInfo{}).AppendTags("disk", disks[index].String())
					ctx := logger.SetReqInfo(GlobalContext, reqInfo)
					logger.LogIf(ctx, err)
				}
				return err
			}
			disksInfo[index] = info
			return nil
		}, index)
	}

	errs = g.Wait()
	// Wait for the routines.
	for i, diskInfoErr := range errs {
		ep := endpoints[i]
		if diskInfoErr != nil {
			offlineDisks[ep]++
			continue
		}
		onlineDisks[ep]++
	}

	// Success.
	return disksInfo, errs, onlineDisks, offlineDisks
}

// Get an aggregated storage info across all disks.
func getStorageInfo(disks []StorageAPI, endpoints []string) (StorageInfo, []error) {
	disksInfo, errs, onlineDisks, offlineDisks := getDisksInfo(disks, endpoints)

	// Sort so that the first element is the smallest.
	sort.Sort(byDiskTotal(disksInfo))

	// Combine all disks to get total usage
	usedList := make([]uint64, len(disksInfo))
	totalList := make([]uint64, len(disksInfo))
	availableList := make([]uint64, len(disksInfo))
	mountPaths := make([]string, len(disksInfo))

	for i, di := range disksInfo {
		usedList[i] = di.Used
		totalList[i] = di.Total
		availableList[i] = di.Free
		mountPaths[i] = di.MountPath
	}

	storageInfo := StorageInfo{
		Used:       usedList,
		Total:      totalList,
		Available:  availableList,
		MountPaths: mountPaths,
	}

	storageInfo.Backend.Type = BackendErasure
	storageInfo.Backend.OnlineDisks = onlineDisks
	storageInfo.Backend.OfflineDisks = offlineDisks

	return storageInfo, errs
}

// StorageInfo - returns underlying storage statistics.
func (xl xlObjects) StorageInfo(ctx context.Context, local bool) (StorageInfo, []error) {

	disks := xl.getDisks()
	endpoints := xl.getEndpoints()
	if local {
		var localDisks []StorageAPI
		var localEndpoints []string
		for i, disk := range disks {
			if disk != nil {
				if disk.IsLocal() {
					// Append this local disk since local flag is true
					localDisks = append(localDisks, disk)
					localEndpoints = append(localEndpoints, endpoints[i])
				}
			}
		}
		disks = localDisks
		endpoints = localEndpoints
	}
	return getStorageInfo(disks, endpoints)
}

// GetMetrics - is not implemented and shouldn't be called.
func (xl xlObjects) GetMetrics(ctx context.Context) (*Metrics, error) {
	logger.LogIf(ctx, NotImplemented{})
	return &Metrics{}, NotImplemented{}
}

// CrawlAndGetDataUsage will start crawling buckets and send updated totals as they are traversed.
// Updates are sent on a regular basis and the caller *must* consume them.
func (xl xlObjects) CrawlAndGetDataUsage(ctx context.Context, bf *bloomFilter, updates chan<- DataUsageInfo) error {
	// This should only be called from runDataCrawler and this setup should not happen (zones).
	return errors.New("xlObjects CrawlAndGetDataUsage not implemented")
}

// CrawlAndGetDataUsage will start crawling buckets and send updated totals as they are traversed.
// Updates are sent on a regular basis and the caller *must* consume them.
func (xl xlObjects) crawlAndGetDataUsage(ctx context.Context, buckets []BucketInfo, bf *bloomFilter, updates chan<- dataUsageCache) error {
	var disks []StorageAPI

	for _, d := range xl.getLoadBalancedDisks() {
		if d == nil || !d.IsOnline() {
			continue
		}
		disks = append(disks, d)
	}
	if len(disks) == 0 || len(buckets) == 0 {
		return nil
	}

	// Load bucket totals
	oldCache := dataUsageCache{}
	err := oldCache.load(ctx, xl, dataUsageCacheName)
	if err != nil {
		return err
	}

	// New cache..
	cache := dataUsageCache{
		Info: dataUsageCacheInfo{
			Name:      dataUsageRoot,
			NextCycle: oldCache.Info.NextCycle,
		},
		Cache: make(map[string]dataUsageEntry, len(oldCache.Cache)),
	}

	// Put all buckets into channel.
	bucketCh := make(chan BucketInfo, len(buckets))
	// Add new buckets first
	for _, b := range buckets {
		if oldCache.find(b.Name) == nil {
			bucketCh <- b
		}
	}
	// Add existing buckets.
	for _, b := range buckets {
		e := oldCache.find(b.Name)
		if e != nil {
			cache.replace(b.Name, dataUsageRoot, *e)
			lc, err := globalLifecycleSys.Get(b.Name)
			activeLC := err == nil && lc.HasActiveRules("", true)
			if activeLC || bf == nil || bf.containsDir(b.Name) {
				bucketCh <- b
			} else {
				if intDataUpdateTracker.debug {
					logger.Info(color.Green("crawlAndGetDataUsage:")+" Skipping bucket %v, not updated", b.Name)
				}
			}
		}
	}

	close(bucketCh)
	bucketResults := make(chan dataUsageEntryInfo, len(disks))

	// Start async collector/saver.
	// This goroutine owns the cache.
	var saverWg sync.WaitGroup
	saverWg.Add(1)
	go func() {
		const updateTime = 30 * time.Second
		t := time.NewTicker(updateTime)
		defer t.Stop()
		defer saverWg.Done()
		var lastSave time.Time

	saveLoop:
		for {
			select {
			case <-ctx.Done():
				// Return without saving.
				return
			case <-t.C:
				if cache.Info.LastUpdate.Equal(lastSave) {
					continue
				}
				logger.LogIf(ctx, cache.save(ctx, xl, dataUsageCacheName))
				updates <- cache.clone()
				lastSave = cache.Info.LastUpdate
			case v, ok := <-bucketResults:
				if !ok {
					break saveLoop
				}
				cache.replace(v.Name, v.Parent, v.Entry)
				cache.Info.LastUpdate = time.Now()
			}
		}
		// Save final state...
		cache.Info.NextCycle++
		cache.Info.LastUpdate = time.Now()
		logger.LogIf(ctx, cache.save(ctx, xl, dataUsageCacheName))
		if intDataUpdateTracker.debug {
			logger.Info(color.Green("crawlAndGetDataUsage:")+" Cache saved, Next Cycle: %d", cache.Info.NextCycle)
		}
		updates <- cache
	}()

	// Start one crawler per disk
	var wg sync.WaitGroup
	wg.Add(len(disks))
	for i := range disks {
		go func(i int) {
			defer wg.Done()
			disk := disks[i]

			for bucket := range bucketCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Load cache for bucket
				cacheName := pathJoin(bucket.Name, dataUsageCacheName)
				cache := dataUsageCache{}
				logger.LogIf(ctx, cache.load(ctx, xl, cacheName))
				if cache.Info.Name == "" {
					cache.Info.Name = bucket.Name
				}
				if cache.Info.Name != bucket.Name {
					logger.LogIf(ctx, fmt.Errorf("cache name mismatch: %s != %s", cache.Info.Name, bucket.Name))
					cache.Info = dataUsageCacheInfo{
						Name:       bucket.Name,
						LastUpdate: time.Time{},
						NextCycle:  0,
					}
				}

				// Calc usage
				before := cache.Info.LastUpdate
				if bf != nil {
					cache.Info.BloomFilter = bf.bytes()
				}
				cache, err = disk.CrawlAndGetDataUsage(ctx, cache)
				cache.Info.BloomFilter = nil
				if err != nil {
					logger.LogIf(ctx, err)
					if cache.Info.LastUpdate.After(before) {
						logger.LogIf(ctx, cache.save(ctx, xl, cacheName))
					}
					continue
				}

				var root dataUsageEntry
				if r := cache.root(); r != nil {
					root = cache.flatten(*r)
				}
				bucketResults <- dataUsageEntryInfo{
					Name:   cache.Info.Name,
					Parent: dataUsageRoot,
					Entry:  root,
				}
				// Save cache
				logger.LogIf(ctx, cache.save(ctx, xl, cacheName))
			}
		}(i)
	}
	wg.Wait()
	close(bucketResults)
	saverWg.Wait()

	return nil
}

// IsReady - shouldn't be called will panic.
func (xl xlObjects) IsReady(ctx context.Context) bool {
	logger.CriticalIf(ctx, NotImplemented{})
	return true
}
