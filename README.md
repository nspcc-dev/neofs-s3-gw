# NeoFS S3 Gateway

NeoFS S3 gateway provides API compatible with Amazon S3 cloud storage service.

## Installation

```go get -u github.com/nspcc-dev/neofs-s3-gw```

Or you can call `make` to build it from the cloned repository (the binary will
end up in `bin/neofs-s3-gw` with authmate helper in `bin/neofs-authmate`).

Notable make targets:

```
dep          Check and ensure dependencies
image        Build clean docker image
dirty-image  Build dirty docker image with host-built binaries
format       Run all code formatters
lint         Run linters
version      Show current version
```

Or you can also use a [Docker
image](https://hub.docker.com/r/nspccdev/neofs-s3-gw) provided for released
(and occasionally unreleased) versions of gateway (`:latest` points to the
latest stable release).

## Execution

Minimalistic S3 gateway setup needs:
 * NeoFS node(s) address (S3 gateway itself is not a NeoFS node)
   Passed via `-p` parameter or via `S3_GW_PEERS_<N>_ADDRESS` and
   `S3_GW_PEERS_<N>_WEIGHT` environment variables (gateway supports multiple
   NeoFS nodes with weighted load balancing).
 * a wallet used to fetch key and communicate with NeoFS nodes
   Passed via `--wallet` parameter or `S3_GW_WALLET` environment variable.

These two commands are functionally equivalent, they run the gate with one
backend node, some keys and otherwise default settings:
```
$ neofs-s3-gw -p 192.168.130.72:8080 --wallet wallet.json

$ S3_GW_PEERS_0_ADDRESS=192.168.130.72:8080 \
  S3_GW_WALLET=wallet.json \
  neofs-s3-gw
```
It's also possible to specify uri scheme (grpc or grpcs) when using `-p` or environment variables:
```
$ neofs-s3-gw -p grpc://192.168.130.72:8080 --wallet wallet.json

$ S3_GW_PEERS_0_ADDRESS=grpcs://192.168.130.72:8080 \
  S3_GW_WALLET=wallet.json \
  neofs-s3-gw
```

## Documentation

- [Configuration](./docs/configuration.md)
- [NeoFS AuthMate](./docs/authmate.md)
- [AWS CLI basic usage](./docs/aws_cli.md)

## S3 API supported

Reference:
* [AWS S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/s3-api.pdf)

### Limitations
#### ACL
For now there are some restrictions:
* [Bucket policy](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html) 
  support only one `Principal` (type `AWS`) per `Statement`. To refer all users use `"AWS": "*"`
* AWS conditions and wildcard are not supported in [resources](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html)
* Only `CanonicalUser` (with hex encoded public key) and `All Users Group` are supported in [ACL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)

### Object

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| CopyObject                | Supported               |
| DeleteObject              | Supported               |
| DeleteObjects             | Supported, aka DeleteMultipleObjects |
| GetObject                 | Supported               |
| GetObjectTorrent          | Unsupported, won't be   |
| HeadObject                | Supported               |
| ListObjectParts           | Unsupported             |
| ListObjects               | Supported               |
| ListObjectsV2             | Supported               |
| PutObject                 | Supported (Content-MD5 option is not supported) |
| SelectObjectContent       | Unsupported             |
| WriteGetObjectResponse    | Unsupported             |

#### ACL

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetObjectAcl              | Supported             |
| PutObjectAcl              | Supported             |

#### Locking

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetObjectLegalHold        | Unsupported             |
| GetObjectLockConfiguration| Unsupported, aka GetBucketObjectLockConfig |
| GetObjectRetention        | Unsupported             |
| PutObjectLegalHold        | Unsupported             |
| PutObjectLockConfiguration| Unsupported, aka PutBucketObjectLockConfig |
| PutObjectRetention        | Unsupported             |

#### Multipart

Should be supported eventually.

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| AbortMultipartUpload      | Unsupported             |
| CompleteMultipartUpload   | Unsupported             |
| CreateMultipartUpload     | Unsupported, aka InitiateMultipartUpload and NewMultipartUpload |
| ListMultipartUploads      | Unsupported             |
| ListParts                 | Unsupported             |
| UploadPart                | Unsupported, aka PutObjectPart  |
| UploadPartCopy            | Unsupported, aka CopyObjectPart |

#### Tagging

Also passed in `PutObject` parameters. We can support adding via `PutObject`
and getting via `GetBucketTagging`, but deleting and putting can't be
supported normally.

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| DeleteObjectTagging       | Unsupported             |
| GetObjectTagging          | Unsupported             |
| PutObjectTagging          | Unsupported             |

#### Versioning

See also `GetObject` and other method parameters.

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| ListObjectVersions        | Supported (null-versioning), aka ListBucketObjectVersions |
| RestoreObject             | Unsupported             |

### Bucket

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| CreateBucket              | Supported, aka PutBucket |
| DeleteBucket              | Supported               |
| GetBucketLocation         | Unsupported             |
| HeadBucket                | Supported               |
| ListBuckets               | Supported               |
| PutPublicAccessBlock      | Unsupported             |

#### Acceleration

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| GetBucketAccelerateConfiguration   | Unsupported, aka GetBucketAccelerate |
| PutBucketAccelerateConfiguration   | Unsupported             |

#### ACL

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetBucketAcl              | Supported             |
| PutBucketAcl              | Supported             |

#### Analytics

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| DeleteBucketAnalyticsConfiguration | Unsupported             |
| GetBucketAnalyticsConfiguration    | Unsupported             |
| ListBucketAnalyticsConfigurations  | Unsupported             |
| PutBucketAnalyticsConfiguration    | Unsupported             |


#### Cors

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| DeleteBucketCors          | Unsupported             |
| GetBucketCors             | Unsupported             |
| PutBucketCors             | Unsupported             |


#### Encryption

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| DeleteBucketEncryption    | Unsupported             |
| GetBucketEncryption       | Unsupported             |
| PutBucketEncryption       | Unsupported             |

#### Inventory

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| DeleteBucketInventoryConfiguration | Unsupported             |
| GetBucketInventoryConfiguration    | Unsupported             |
| ListBucketInventoryConfigurations  | Unsupported             |
| PutBucketInventoryConfiguration    | Unsupported             |

#### Lifecycle

| Method                          | Status                  |
| ------------------------------- | ----------------------- |
| DeleteBucketLifecycle           | Unsupported             |
| GetBucketLifecycle              | Unsupported             |
| GetBucketLifecycleConfiguration | Unsupported             |
| PutBucketLifecycle              | Unsupported             |
| PutBucketLifecycleConfiguration | Unsupported             |

#### Logging

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetBucketLogging          | Unsupported             |
| PutBucketLogging          | Unsupported             |

#### Metrics

| Method                           | Status                  |
| -------------------------------- | ----------------------- |
| DeleteBucketMetricsConfiguration | Unsupported             |
| GetBucketMetricsConfiguration    | Unsupported             |
| ListBucketMetricsConfigurations  | Unsupported             |
| PutBucketMetricsConfiguration    | Unsupported             |

#### Notifications

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| GetBucketNotification              | Unsupported             |
| GetBucketNotificationConfiguration | Unsupported             |
| ListenBucketNotification           | Unsupported, non-standard? |
| PutBucketNotification              | Unsupported             |
| PutBucketNotificationConfiguration | Unsupported             |

#### Ownership controls

| Method                        | Status                  |
| ----------------------------- | ----------------------- |
| DeleteBucketOwnershipControls | Unsupported             |
| GetBucketOwnershipControls    | Unsupported             |
| PutBucketOwnershipControls    | Unsupported             |

#### Policy and replication

| Method                  | Status                  |
| ----------------------- | ----------------------- |
| DeleteBucketPolicy      | Unsupported             |
| DeleteBucketReplication | Unsupported             |
| DeletePublicAccessBlock | Unsupported             |
| GetBucketPolicy         | Supported             |
| GetBucketPolicyStatus   | Unsupported             |
| GetBucketReplication    | Unsupported             |
| PostPolicyBucket        | Unsupported, non-standard? |
| PutBucketPolicy         | Supported             |
| PutBucketReplication    | Unsupported             |

#### Request payment

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetBucketRequestPayment   | Unsupported             |
| PutBucketRequestPayment   | Unsupported             |

#### Tagging

| Method                  | Status                  |
| ----------------------- | ----------------------- |
| DeleteBucketTagging     | Unsupported             |
| GetBucketTagging        | Unsupported             |
| PutBucketTagging        | Unsupported             |

#### Tiering

| Method                                         | Status                  |
| ---------------------------------------------- | ----------------------- |
| DeleteBucketIntelligentTieringConfiguration    | Unsupported             |
| GetBucketIntelligentTieringConfiguration       | Unsupported             |
| ListBucketIntelligentTieringConfigurations     | Unsupported             |
| PutBucketIntelligentTieringConfiguration       | Unsupported             |

#### Versioning

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetBucketVersioning       | Unsupported             |
| PutBucketVersioning       | Unsupported             |

#### Website

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| DeleteBucketWebsite       | Unsupported             |
| GetBucketWebsite          | Unsupported             |
| PutBucketWebsite          | Unsupported             |
