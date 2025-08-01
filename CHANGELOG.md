# Changelog

This document outlines major changes between releases.

## [Unreleased]

### Added

### Changed

### Fixed
- Incorrect EpochDuration processing wrt API 2.18 leading to improper expiration calculations (#1193)

### Updated

### Removed

### Upgrading from 0.40.0

## [0.40.0] - 2025-07-24

### Changed
- __NEOFS__ASSOCIATE attribute is used for locks and tags now (#1189, #1190)

### Fixed
- Incompatibility with NeoFS node 0.48.0 for lock objects (#1189)

## [0.39.0] - 2025-07-11

### Added
- `logger.sampling.enabled` config option (#1179)

### Fixed
- Incorrect handling of tags in unversioned buckets (#1185)

### Updated
- `github.com/nspcc-dev/neofs-sdk-go` dependency to `v1.0.0-rc.13.0.20250710125524-3779db10c349` (#1186)
- NeoFS SDK to v1.0.0-rc.13.0.20250709105423-10781475208e (#1186)
- github.com/aws/aws-sdk-go-v2 from v1.36.3 to v1.36.5 (#1186)
- github.com/nspcc-dev/neo-go from v0.108.1 to v0.110.0 (#1186)
- github.com/nspcc-dev/neofs-contract from v0.21.0 to v0.23.0 (#1186)

### Removed
- Container attribute with owner public key (#1182)

## [0.38.0] - 2025-05-30

### Changed
- Optimized lock metadata storage (#1168)
- Optimized searches for tag and lock objects (#1167)
- Tags are stored as object attributes now (#1166)

### Fixed
- Internal slicer not working correctly with 0.46.0+ NeoFS (#1170, #1173)
- Meta objects not deleted when deleting an object (#1169)
- S3 listing pagination issues (#1177)

### Updated
- NeoFS SDK to v1.0.0-rc.13.0.20250516065036-cd732ce85922 (#1173)

### Removed
- MetaType=lock attribute from lock objects (#1176)

## [0.37.0] - 2025-05-12

### Added
- Support of `x-amz-content-sha256` header with `STREAMING-UNSIGNED-PAYLOAD-TRAILER` value (#1028)
- Fetching metadata consistency policy from contract (#1150)

### Changed
- Request-related metrics are histograms now (#1127)
- Bucket ownership settings moved from EACL to bucket settings meta objects (#1120)
- Bucket settings data is versioned now (#1143)
- Unified prefixes for object attributes (#1145)
- Peers list definition in config files (#1149)
- Object's Epoch attribute is no longer considered when sorting (only timestamp is used, #1163)
- ChaCha20-Poly1305 is replaced by AES for access boxes (#1136)

### Fixed
- Requirement to pass Content-MD5 header when deleting multiple objects (#1113)
- Missing prefix in ListObjectVersions result (#1128)
- Duplicates in object listings (#1133)
- Incorrect ownership of multipart upload metadata objects (#1139)
- Homomorphic hashing enabled for new bucket when it's disabled network-wide (#1138)
- Attempt to list whole bucket when removing it (#1157)

### Updated
- AWS SDK to V2 (#1028)

### Removed
- MetaMultipartType object attribute (#1146)

### Upgrading from 0.36.1
authmate tool "reset-bucket-acl" command was updated to clean redundant EACL records. These settings were moved to
bucket settings object.

Please change peer config from the old format:
```yaml
peers:
  0:
    address: node1.neofs:8080
    priority: 1
    weight: 1
```
to the new one:
```yaml
peers:
  - address: node1.neofs:8080
    priority: 1
    weight: 1
```

## [0.36.1] - 2025-04-09

### Fixed
- Performance regresssion relative to 0.35.0 caused by incorrect settings cache (#1121)
- Incorrect 500 status code for unsuccessful object puts caused by missing access permissions (#1121)

## [0.36.0] - 2025-04-04

This release no longer uses the experimental tree service for any operations,
so it can be used with any standard 0.45.0+ NeoFS node. Some fixes and
configuration improvements are included as well.

### Added
- `logger.encoding` config option (#1100)
- `logger.timestamp` config option (#1100)
- Experimental `neofs.metadata_policy` config option (#1117)

### Changed
- Bucket settings storage scheme (#1104, #1106, #1109, #1107)

### Fixed
- Some missing metrics (#1098)
- Locks and tags for versioned objects (#1110)
- Inability to get object because of incorrect access rights (#1112)
- Object copying in versioned buckets (#1114)

### Updated
- github.com/urfave/cli/v2 dependency to v2.27.6 (#1095)
- github.com/prometheus/client_golang dependency to v1.21.1 (#1095)
- github.com/spf13/pflag dependency to v1.0.6 (#1095)
- google.golang.org/grpc dependency to v1.71.0 (#1095)

### Removed
- neofs.epoch_update_interval option (#1094)
- tree option (#1070)
- Some unused object attributes (#1097)

## [0.35.0] - 2025-03-07

This is a hybrid version for test purposes only, it no longer uses
experimental tree extension of NeoFS for object operations, but it still needs
it for some bucket-level operations. A number of other improvements went in as
well, this version offers adequate performance using pure native NeoFS APIs.

### Changed
- GetBucketLifecycle operation now partially supported. It always returns NoSuchLifecycleConfiguration error (#1049)
- Minimal required Go is 1.23 now (#979, #1092)
- Object operations no longer use tree service (#1050, #1066, #1067, #1068)
- Gateway uses SearchV2 now for internal purposes (#1082)
- Optimized GetObject (#1085)

### Fixed
- CopyObject with enabled versioning (#1075)
- Missing version metric on application start (#1089)
- CompleteMultipartUpload incompatibility with some clients (#1077)

### Updated
- `github.com/nspcc-dev/neofs-sdk-go` dependency to `v1.0.0-rc.13` (#1073, #1088, #1092)
- `github.com/nspcc-dev/neo-go` dependency to `v0.108.1` (#1092)
- `google.golang.org/grpc` dependency to `v1.70.0` (#1092)
- `google.golang.org/protobuf` dependency to `v1.36.5` (#1092)
- `github.com/stretchr/testify` dependency to `v1.10.0` (#1092)
- `golang.org/x/sync` to `v0.11.0` (#1092)
- `golang.org/x/exp` to `v0.0.0-20250210185358-939b2ce775ac` (#1092)

## [0.34.1] - 2025-01-27

### Fixed
- CopyObject returning "duplicate attributes" error in some cases (#1058)
- EACL overflow in CopyObject (#1061)

## Upgrading from 0.34.0
authmate tool was extended with "reset-bucket-acl" command to fix erroneously
big EACLs in containers, use it in case you have a container with this problem.

## [0.34.0] - 2024-12-30

### Changed
- Disable URI path escaping for presigned URLs (#1046)

### Updated
- golang.org/x/crypto dependency from 0.26.0 to 0.31.0 (#1044)

### Removed
- Command generate-presigned-url from authmate (#1048)

## [0.33.0] - 2024-12-10

### Changed
- ACLs are disabled now by default (like in AWS S3), but can be enabled via policy (#1018, #1026, #1036)
- Log sampling is disabled now (#1024)
- Concurrent parts upload is possible now for multipart uploads (#1034, #1041)
- neofs_s3_version_info metric renamed to neofs_s3_version (#1035)

### Fixed
- authmate not checking for URL validity when creating presigned URL (#1027)
- Panic in chunked encoding handler (#1039)

### Updated
- NeoGo dependency to 0.107.0 (#1040)

## [0.32.0] - 2024-10-01

### Added
- placement_policy.locations config option (#989)
- Placement policy search using contract (#999)

### Fixed
- Reading chunked payload if header content-encoding: aws-chunked is not set (#1009)

## [0.31.1] - 2024-09-13

### Added

### Changed
- Documentation for extensions and unsupported features (#990, #991, #995, #998)
- Go 1.22+ is required to build now (#927)
- stream_timeout default timeout from 10s to 60s (#973)
- Multipart objects are signed directly by gate now (#1001)

### Fixed
- Incorrect locked object deletion (#992)
- Potential version ID collisions in some cases (#993)
- Excessive memory use when working with small objects (#997)

### Updated
- github.com/minio/sio from v0.4.0 to v0.4.1 (#927)
- github.com/nats-io/nats.go from v1.34.0 to v1.37.0 (#927)
- github.com/nspcc-dev/tzhash from v1.8.1 to v1.8.2 (#927)
- github.com/prometheus/client_golang from v1.20.0 to v1.20.2 (#927)
- github.com/urfave/cli/v2 from v2.27.2 to v2.27.4 (#927)

## [0.31.0] - 2024-08-20

### Added
- Use HKDF salt and info (#972)
- Allow addresses to be used in EACLs (#976)

### Updated
- github.com/nspcc-dev/neofs-sdk-go dependency from v1.0.0-rc.12 to v1.0.0-rc.12.0.20240807160341-3528eb5bb1cc

### Changed
- Single `rpc_endpoint` config option replaced with multiple endpoints `fschain.endpoints` option (#968)
- Go 1.21+ is required to build now (#811)
- Replaced HTTP 500 with HTTP 400 if user.ID decode failed (#983)

### Updated
- github.com/nspcc-dev/neo-go dependency from v0.106.2 to v0.106.3 (#811)
- github.com/urfave/cli/v2 dependency from v2.3.0 to v2.27.2 (#811)
- github.com/nspcc-dev/neofs-contract dependency from v0.19.2-0.20240610103236-d50c8e0c9396 to v0.20.0 (#811)
- golang.org/x/crypto dependency from v0.21.0 to v0.26.0 (#811)
- github.com/nspcc-dev/tzhash dependency from v1.8.0 to v1.8.1 (#811)
- github.com/prometheus/client_golang dependency from v1.19.0 to v1.20.0 (#811)
- google.golang.org/protobuf dependency from v1.33.0 to v1.34.2 (#811)
- github.com/panjf2000/ants/v2 dependency from v2.5.0 to v2.10.0 (#811)
- github.com/aws/aws-sdk-go dependency from v1.50.27 to v1.55.5 (#811)
- github.com/spf13/viper dependency from v1.18.2 to v1.19.0 (#811)
- github.com/nats-io/nats.go dependency from v1.31.0 to v1.34.0 (#811)
- google.golang.org/grpc dependency from v1.62.0 to v1.62.1 (#811)
- github.com/minio/sio dependency from v0.3.0 to v0.4.0 (#811)

### Fixed
- Save hashless object header in SpitV2 (#974)
- Clean actual object version (#970)

### Updating from 0.30.1
- Old access boxes are incompatible with this version.
- The gate compatible only with node 0.43.0+.

Notice that the configuration parameter `fschain.endpoints` contains multiple endpoints.
For migration, you should update config from old notation
```yaml
rpc_endpoint: http://some-host:30333
```
to the new one
```yaml
fschain:
  endpoints:
    - http://some-host:30333
```

## [0.30.1] - 2024-06-19

### Added
- ARM64 and Darwin binaries (#949)

### Changed
- Split object scheme for multipart uploads to v2 scheme (#957)
- Timestamp is hidden if program is not running in TTY (#965)

### Fixed
- Inability to use "*" in ACLs (#958)
- Useless EACL record (#961)
- Incorrect owner returned for versioned/multipart objects (#957)
- Incorrect size retured for encrypted objects (#957)
- OPTIONS handling for pre-auth requests (#964)

### Updated
- Documentation (#946)
- NeoFS SDK to RC12 (#943, #940, #960)
- golang.org/x/net dependency from 0.21.0 to 0.23.0 (#948)
- NeoGo dependency to 0.106.2 (#956, #960, #963)

## [0.30.0] - 2024-03-27

### Added
- Preallocate buffers to object uploads (#835)
- Support for aws-chunked (#914)
- Store CORS to the object (#890)

### Changed
- Go 1.20+ is required to build now, using 1.22 by default (#928, #933)
- Limit objects amount for DeleteObjects (#849)
- Actualize CODEOWNERS (#942)
- Passing an empty meta parameter value raises "Your metadata headers are not supported." error (#848)
- Sdk optimizations (#839)
- Store bucket owner pub key in container attributes. It helps to process ACL correctly (#915)

### Updated
- Documentation about ETag (#856)
- Use SDK with pool base multi sessions (#855)
- Documentation about Authenticated Users group (#871)
- SDK to use slicing optimization (#923)
- Don't use neofs-crypto directly in neofs/tree (#932)
- build(deps): bump golang.org/x/net from 0.14.0 to 0.17.0 (#851)
- build(deps): bump github.com/nats-io/nats-server/v2 from 2.7.4 to 2.9.23 (#867)
- build(deps): bump google.golang.org/grpc from 1.57.0 to 1.57.1 (#880)
- build(deps): bump github.com/nats-io/nkeys from 0.4.4 to 0.4.6 (#894)
- build(deps): bump golang.org/x/crypto from 0.14.0 to 0.17.0 (#917)
- build(deps): bump google.golang.org/protobuf from 1.31.0 to 1.33.0 (#935)

### Removed
- 'v' from app version (#922)
- re-slicing for multipart (#931)

### Fixed
- Makefile: Fix sync-tree (#941)
- Correct filePath attribute filter using, storing only uniq pubKey in ACL target rule (#876)
- Public read acl results in full control permission (#866)
- Restrict presigned URL lifetime (#883)
- Return unsupported error on GetObjectTorrent (#884)
- Return unsupported error on GetBucketPolicyStatus (#886)
- Return unsupported error on PutPublicAccessBlock (#887)
- Return the correct error, if x-amz-credential is not provided (#892)
- Not accurate error message for invalid authenticated requests (#882)
- Return error if no tags in bucket (#924)
- Return correct error on invalid grantee type (#926)
- Sort parts by number and server creation time, for correct detection part if it was re-uploaded (#929)
- Return correct error on lock configuration check (#888)
- Return unimplemented error on GetPublicAccessBlock (#896)
- Return unimplemented error in PutBucketLogging (#925)
- Return not supported error for PutObjectLegalHold command if OFF state (#889)
- Check x-amz-expires header on maximum border (#893)
- Handle bad user id more gracefully (#879)

## [0.29.0] - 2023-09-28

### Added
- Experimental "internal-slicer" option to prepare objects on the gateway side (#831)

### Changed
- Go 1.19+ is required to build now, using 1.21 by default (#829)
- NeoGo dependency updated to 0.102.0 (#829)

### Removed
- Setting System EACL rules (#825)
- NoOp compatibility resolver, RPC endpoint configuration is mandatory now (#830)

## [0.28.2] - 2023-09-13

### Fixed
- Panic when creating some objects (#821)
- SDK updated to fix node health management issues and count statistics more appropriately (#823)

## [0.28.1] - 2023-09-08

### Updated
- `neofs-sdk-go` to `v1.0.0-rc.11`

## [0.28.0] - 2023-08-25

### Fixed
- Authmate panic in case of some missing parameters (#794)
- Missing reconnects in case of RPC connection failure (#796)
- Failure to complete multipart upload of ACL-enabled object (#807)

### Added
- NoOpResolver as backward compatibility for case when rpc_endpoint/S3_GW_RPC_ENDPOINT param is empty in config, it will be removed in 0.29.0 (#807)

### Changed
- Improved documentation (#795)
- Renamed API errors package (#803)
- Docker image is more lightweight now (#804)
- Option `rpc_endpoint` in yaml config or `S3_GW_RPC_ENDPOINT` in env config is mandatory (#807).
- SDK dependency updated to RC10 (#807)
- Improved data buffering (#807)

### Removed
- Options `resolve_order` in yaml config and `S3_GW_RESOLVE_ORDER` in env (#807).

## [0.27.1] - 2023-06-15

### Fixed
- authmate panic (#787)
- wrong return code logged for PutBucketVersioning (#792)

### Changed
- SDK dependency updated to RC9+ (#785, #789)

## [0.27.0] - 2023-05-19

### Fixed
- Grantee XML decoding (#768)

### Added
- Version metric (#779)

### Changed
- Go 1.17 is no longer supported, 1.20 used by default for builds (#776)
- SDK dependency is now at 1.0.0-rc.8 (#777)
- golang.org/x/net dependency is now at 0.10.0 fixing some security issues there (#777)
- github.com/nats-io/nats-server/v2 update to 2.7.4 fixing CVE-2022-26652 (#778)

### Removed

## [0.26.1] - 2023-02-22

### Fixed
- Incorrect error count in pool component (#767)

## [0.26.0] - 2022-12-28

### Added
- Use client time as `now` in some requests (#726)
- Reload policies on SIGHUP (#747)
- Authmate flags for pool timeouts (#760)
- Multiple server listeners (#742)

### Changed
- Placement policy configuration (#568)
- Improved debug logging of CID and OID values (#754)

### Removed
- Deprecated linters (#755)

### Updating from v0.25.1
New config parameters were added. And old one `defaul_policy` were changed.
```yaml
placement_policy:
  default: "REP 3"
  region_mapping: /path/to/container/policies.json
```

Make sure you update the config accordingly:
If you configure application using environment variables change:
* `S3_GW_DEFAULT_POLICY` -> `S3_GW_PLACEMENT_POLICY_DEFAULT_POLICY`
* `S3_GW_LISTEN_ADDRESS` -> `S3_GW_SERVER_0_ADDRESS`
* `S3_GW_TLS_CERT_FILE` -> `S3_GW_SERVER_0_TLS_CERT_FILE` (and set `S3_GW_SERVER_0_TLS_ENABLED=true`)
* `S3_GW_TLS_KEY_FILE` -> `S3_GW_SERVER_0_TLS_KEY_FILE` (and set `S3_GW_SERVER_0_TLS_ENABLED=true`)

If you configure application using `.yaml` file change:
* `defaul_policy` -> `placement_policy.default`
* `listen_address` -> `server.0.address`
* `tls.cert_file` -> `server.0.tls.cert_file` (and set `server.0.tls.enabled: true`)
* `tls.key_file` -> `server.0.tls.key_file` (and set `server.0.tls.enabled: true`)

## [0.25.1] - 2022-10-30

### Fixed
- Empty bucket policy (#740)
- Big object removal (#749)
- Checksum panic (#741)

### Added
- Debian packaging (#737)
- Timeout for individual operations in streaming RPC (#750)

## [0.25.0] - 2022-10-31

### Fixed
- Legal hold object lock enabling (#709)
- Errors at object locking (#719)
- Unrestricted access to not owned objects via cache (#713)
- Check tree service health (#699)
- Bucket names in listing (#733)

### Added
- Config reloading on SIGHUP (#702, #715, #716)
- Stop pool dial on SIGINT (#712)

### Changed
- GitHub actions update (#710)
- Makefile help (#725)
- Optimized object tags setting (#669) 
- Improved logging (#728)
- Unified unit test names (#617)
- Improved docs (#732)

### Removed
- Unused cache methods (#650)

### Updating from v0.24.0
New config parameters were added. Make sure the default parameters are appropriate for you.

```yaml
cache:
  accesscontrol:
    lifetime: 1m
    size: 100000
```

## [0.24.0] - 2022-09-14

### Added
- Exposure of pool metrics (#615, #680)
- Configuration of `set_copies_number` (#634, #637)
- Configuration of list of allowed `AccessKeyID` prefixes (#674)
- Tagging directive for `CopyObject` (#666, #683)
- Customer encryption (#595)
- `CopiesNumber` configuration (#634, #637)

### Changed
- Improved wallet configuration via `.yaml` config and environment variables (#607)
- Update go version for build to 1.19 (#694, #705)
- Update version calculation (#653, #697)
- Optimized lock creation (#692)
- Update way to configure `listen_domains` (#667)
- Use `FilePath` instead of `FileName` for object keys (#657)
- Optimize listing (#625, #616)

### Removed
- Drop any object search logic (#545)

### Fixed
- Responses to `GetObject` and `HeadObject`: removed redundant `VersionID` (#577, #682)
- Replacement of object tagging in case of overwriting of an object (#645)
- Using tags cache with empty `versionId` (#643)
- Fix panic on go1.19 (#678)
- Fix panic on invalid versioning status (#660)
- Fix panic on missing decrypt reader (#704)
- Using multipart uploads with `/` in name (#671)
- Don't update settings cache when request fails (#661)
- Fix handling `X-Amz-Copy-Source` header (#672)
- ACL related problems (#676, #606)
- Using `ContinuationToken` for "directories" (#684)
- Fix `connection was closed` error (#656)
- Fix listing for nested objects (#624)
- Fix anon requests to tree service (#504, #505)

### Updating from v0.23.0
Make sure your configuration is valid:

If you configure application using environment variables change:
* `S3_GW_WALLET` -> `S3_GW_WALLET_PATH`
* `S3_GW_ADDRESS` -> `S3_GW_WALLET_ADDRESS`
* `S3_GW_LISTEN_DOMAINS_N` -> `S3_GW_LISTEN_DOMAINS` (use it as array variable)

If you configure application using `.yaml` file change:
* `wallet` -> `wallet.path` 
* `address` -> `wallet.address`
* `listen_domains.n` -> `listen_domains` (use it as array param)


## [0.23.0] - 2022-08-01

### Fixed
- System metadata are filtered now (#619)
- List objects in corner cases (#612, #627)
- Correct removal of a deleted object (#610)
- Bucket creation could lead to "no healthy client" error (#636)

### Added
- New param to configure pool error threshold (#633)

### Changed
- Pprof and prometheus metrics configuration (#591)
- Don't set sticky bit in authmate container (#540)
- Updated compatibility table (#638)
- Rely on string sanitizing from zap (#498)

### Updating from v0.22.0
1. To enable pprof use `pprof.enabled` instead of `pprof` in config. 
To enable prometheus metrics use `prometheus.enabled` instead of `metrics` in config. 
If you are using the command line flags you can skip this step.

## [0.22.0] - 2022-07-25

Tree service support

### Fixed
- Error logging (#450)
- Default bucket location constraint (#463)
- Suspended versioning status (#462)
- CodeQL warnings (#489, #522, #539)
- Bearer token behaviour with non-owned buckets (#459)
- ACL issues (#495, #553, #571, #573, #574, #580)
- Authmate policy parsing (#558)

### Added
- Public key output in authmate issue-secret command (#482)
- Support of conditional headers (#484)
- Cache type cast error logging (#465)
- `docker/*` target in Makefile (#471)
- Pre signed requests (#529)
- Tagging and ACL notifications (#361) 
- AWSv4 signer package to improve compatibility with S3 clients (#528)
- Extension mimetype detector (#289)
- Default params documentation (#592)
- Health metric (#600)
- Parallel object listing (#525)
- Tree service (see commit links from #609)

### Changed
- Reduce number of network requests (#439, #441)
- Renamed authmate to s3-authmate (#518)
- Version output (#578)
- Improved error messages (#539)

### Removed
- `layer/neofs` package (#438)

## [0.21.1] - 2022-05-16

### Changed
- Update go version to go1.17 (#427)
- Set homomorphic hashing disable attribute in container if required (#435)

## [0.21.0] - 2022-05-13

### Added
- Support of get-object-attributes (#430)

### Fixed
- Reduced time of bucket creation (#426)
- Bucket removal (#428)
- Obtainment of ETag value (#431)

### Changed
- Authmate doesn't parse session context anymore, now it accepts application defined 
  flexible structure with container ID in human-readable format (#428)

## [0.20.0] - 2022-04-29

### Added
- Support of object locking (#195)  
- Support of basic notifications (#357, #358, #359)

### Changed
- Logger behavior: now it writes to stderr instead of stdout, app name and 
  version are always presented and fixed, all user options except of `level` are 
  dropped (#380)
- Improved docs, added config examples (#396, #398)
- Updated NeoFS SDK (#365, #409)

### Fixed
- Added check of `SetEACL` tokens before processing of requests (#347)
- Authmate: returned lost session tokens when a parameter `--session-token` is 
  omitted (#387)
- Error when a bucket hasn't a settings file (#389)
- Response to a request to delete not existing object (#392)
- Replaced gate key in ACL Grantee by key of bearer token issuer (#395) 
- Missing attach of bearer token to requests to put system object (#399)
- Deletion of system object while CompleteMultipartUpload (#400)
- Improved English in docs and comments (#405)
- Authmate: reconsidered default bearer token rules (#406)

## [0.19.0] - 2022-03-16

### Added
- Authmate: support placement policy overriding (#343, #364)
- Managing bucket notification configuration (#340)
- Unit tests in go1.17 (#265)
- NATS settings in application config (#341)
- Support `Expires` and `Cache-Control` headers (#312)
- Support `%` as delimiter (#313)
- Support `null` version deletion (#319)
- Bucket name resolving order (#285)
- Authmate: added `timeout` flag (#290)
- MinIO results in s3 compatibility tables (#304)
- Support overriding response headers (#310)

### Changed
- Authmate: check parameters before container creation (#372)
- Unify cache invalidation on deletion (#368)
- Updated NeoFS SDK to v1.0.0-rc.3 (#297, #333, #346, #376)
- Authmate: changed session token rules handling (#329, #336, #338, #352)
- Changed status code for some failed requests (#308)
- GetBucketLocation returns policy name used at bucket creation (#301) 

### Fixed
- Waiting for bucket to be deleted (#366)
- Authmate: changed error message for session context building (#348)
- Authmate: fixed access key parsing in `obtain-secret` command (#295)
- Distinguishing `BucketAlreadyExists` errors (#354)
- Incorrect panic if handler not found (#305)
- Authmate: use container friendly name as system name (#299, #324)
- Use UTC `Last-Modified` timestamps (#331)
- Don't return object system metadata (#307)
- Handling empty post policy (#306)
- Use `X-Amz-Verion-Id` in `CompleteMulipartUpload` (#318)

### Removed
- Drop MinIO related errors (#316)

## [0.18.0] - 2021-12-16

### Added
- Support for MultipartUpload (#186, #187) 
- CORS support (#217)
- Authmate supports setting of tokens lifetime in a more convenient format (duration) (#258)
- Generation of a random key for `--no-sign-request` (#276)

### Changed
- Bucket name resolving mechanism from listing owner's containers to using DNS (#219)

### Removed
- Deprecated golint, replaced by revive (#272)

## 0.17.0 (24 Sep 2021)
With this release we introduce [ceph-based](https://github.com/ceph/s3-tests) S3 compatibility results.

### Added
* Versioning support (#122, #242, #263)
* Ceph S3 compatibility results (#150, #249, #266)
* Handling `X-Amz-Expected-Bucket-Owner` header (#216)
* `X-Container-Id` header for `HeadBucket` response (#220)
* Basic ACL support (#49, #213)
* Caching (#179, #206, #231, #236, #253)
* Metadata directive when copying (#191)
* Bucket name checking (189)
* Continuation token support (#112, #154, #180)
* Mapping `LocationConstraint` to `PlacementPolicy` (#89)
* Tagging support (#196)
* POST uploading support (#190)
* Delete marker support (#248)
* Expiration for access box (#255)
* AWS CLI credential generating by authmate (#241) 

### Changed
* Default placement policy is now configurable (#218) 
* README is split into different files (#210)
* Unified error handling (#89, #149, #184)
* Authmate issue-secret response contains container id (#163)
* Removed "github.com/nspcc-dev/neofs-node" dependency (#234)
* Removed GitHub workflow of image publishing (#243)
* Changed license to AGPLv3 (#264)

### Fixed
* ListObjects results are now the same for different users (#230)
* Error response for invalid authentication header is now correct (#199)
* Saving object metadata (#198)
* Range header handling (#194)
* Correct status codes (#118, #262)
* HeadObject for "directories" (#160)
* Fetch-owner parameter support (#159)

## 0.16.0 (16 Jul 2021)

With this release we publish S3 gateway source code. It includes various S3
compatibility improvements, support of bucket management, unified secp256r1
cryptography with NEP-6 wallet support.

### Fixed
 * Allowed no-sign request (#65)
 * Bearer token attached to all requests (#84)
 * Time format in responses (#133)
 * Max-keys checked in ListObjects (#135)
 * Lost metadat in the objects (#131)
 * Unique bucket name check (#125)

### Added
 * Bucket management operations (#47, #72)
 * Node-specific owner IDs in bearer tokens (#83)
 * AWS CLI usage section in README (#77)
 * List object paging (#97)
 * Lifetime for the tokens in auth-mate (#108)
 * Support of range in GetObject request (#96)
 * Support of NEP-6 wallets instead of binary encoded keys (#92)
 * Support of JSON encoded rules in auth-mate (#71)
 * Support of delimiters in ListObjects (#98)
 * Support of object ETag (#93)
 * Support of time-based conditional CopyObject and GetObject (#94)

### Changed
 * Accesskey format: now `0` used as a delimiter between container ID and object 
   ID instead of `_` (#164)
 * Accessbox is encoded in protobuf format (#48)
 * Authentication uses secp256r1 instead of ed25519 (#75)
 * Improved integration with NeoFS SDK and NeoFS API Go (#78, #88)
 * Optimized object put execution (#155)

### Removed
 * GRPC keepalive options (#73)

## 0.15.0 (10 Jun 2021)

This release brings S3 gateway to the current state of NeoFS and fixes some
bugs, no new significant features introduced (other than moving here already
existing authmate component).

New features:
 * authmate was moved into this repository and is now built along with the
   gateway itself (#46)

Behavior changes:
 * neofs-s3-gate was renamed to neofs-s3-gw (#50)

Improvements:
 * better Makefile (#43, #45, #55)
 * stricter linters (#45)
 * removed non-standard errors package from dependencies (#54)
 * refactoring, reusing new sdk-go component (#60, #62, #63)
 * updated neofs-api-go for compatibility with current NeoFS node 0.21.0 (#60, #68)
 * extended README (#67, #76)

Bugs fixed:
 * wrong (as per AWS specification) access key ID generated (#64)

## Older versions

Please refer to [Github
releases](https://github.com/nspcc-dev/neofs-s3-gw/releases/) for older
releases.

[0.18.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.17.0...v0.18.0
[0.19.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.18.0...v0.19.0
[0.20.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.19.0...v0.20.0
[0.21.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.20.0...v0.21.0
[0.21.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.21.0...v0.21.1
[0.22.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.21.1...v0.22.0
[0.23.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.22.0...v0.23.0
[0.24.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.23.0...v0.24.0
[0.25.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.24.0...v0.25.0
[0.26.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.25.0...v0.26.0
[0.26.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.26.0...v0.26.1
[0.27.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.26.1...v0.27.0
[0.27.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.27.0...v0.27.1
[0.28.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.27.1...v0.28.0
[0.28.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.28.0...v0.28.1
[0.28.2]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.28.1...v0.28.2
[0.29.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.28.2...v0.29.0
[0.30.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.29.0...v0.30.0
[0.30.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.30.0...v0.30.1
[0.31.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.30.1...v0.31.0
[0.31.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.31.0...v0.31.1
[0.32.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.31.1...v0.32.0
[0.33.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.32.0...v0.33.0
[0.34.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.33.0...v0.34.0
[0.34.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.34.0...v0.34.1
[0.35.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.34.1...v0.35.0
[0.36.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.35.0...v0.36.0
[0.36.1]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.36.0...v0.36.1
[0.37.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.36.1...v0.37.0
[0.38.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.37.0...v0.38.0
[0.39.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.38.0...v0.39.0
[0.40.0]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.39.0...v0.40.0
[Unreleased]: https://github.com/nspcc-dev/neofs-s3-gw/compare/v0.40.0...master
