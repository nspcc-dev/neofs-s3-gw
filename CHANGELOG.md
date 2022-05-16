# Changelog

This document outlines major changes between releases.

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
