## S3 API support

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

| Method                    | Status                                          |
| ------------------------- | -----------------------                         |
| CopyObject                | Supported                                       |
| DeleteObject              | Supported                                       |
| DeleteObjects             | Supported, aka DeleteMultipleObjects            |
| GetObject                 | Supported                                       |
| GetObjectTorrent          | Unsupported, won't be                           |
| HeadObject                | Supported                                       |
| ListObjectParts           | Unsupported                                     |
| ListObjects               | Supported                                       |
| ListObjectsV2             | Supported                                       |
| PutObject                 | Supported (Content-MD5 option is not supported) |
| SelectObjectContent       | Unsupported                                     |
| WriteGetObjectResponse    | Unsupported                                     |

#### ACL

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetObjectAcl              | Supported               |
| PutObjectAcl              | Supported               |

#### Locking

| Method                     | Status                                     |
| -------------------------  | -----------------------                    |
| GetObjectLegalHold         | Unsupported                                |
| GetObjectLockConfiguration | Unsupported, aka GetBucketObjectLockConfig |
| GetObjectRetention         | Unsupported                                |
| PutObjectLegalHold         | Unsupported                                |
| PutObjectLockConfiguration | Unsupported, aka PutBucketObjectLockConfig |
| PutObjectRetention         | Unsupported                                |

#### Multipart

Should be supported eventually.

| Method                    | Status                                                          |
| ------------------------- | -----------------------                                         |
| AbortMultipartUpload      | Unsupported                                                     |
| CompleteMultipartUpload   | Unsupported                                                     |
| CreateMultipartUpload     | Unsupported, aka InitiateMultipartUpload and NewMultipartUpload |
| ListMultipartUploads      | Unsupported                                                     |
| ListParts                 | Unsupported                                                     |
| UploadPart                | Unsupported, aka PutObjectPart                                  |
| UploadPartCopy            | Unsupported, aka CopyObjectPart                                 |

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

| Method                    | Status                                                    |
| ------------------------- | -----------------------                                   |
| ListObjectVersions        | Supported (null-versioning), aka ListBucketObjectVersions |
| RestoreObject             | Unsupported                                               |

### Bucket

| Method                    | Status                   |
| ------------------------- | -----------------------  |
| CreateBucket              | Supported, aka PutBucket |
| DeleteBucket              | Supported                |
| GetBucketLocation         | Unsupported              |
| HeadBucket                | Supported                |
| ListBuckets               | Supported                |
| PutPublicAccessBlock      | Unsupported              |

#### Acceleration

| Method                             | Status                               |
| ---------------------------------- | -----------------------              |
| GetBucketAccelerateConfiguration   | Unsupported, aka GetBucketAccelerate |
| PutBucketAccelerateConfiguration   | Unsupported                          |

#### ACL

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetBucketAcl              | Supported               |
| PutBucketAcl              | Supported               |

#### Analytics

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| DeleteBucketAnalyticsConfiguration | Unsupported             |
| GetBucketAnalyticsConfiguration    | Unsupported             |
| ListBucketAnalyticsConfigurations  | Unsupported             |
| PutBucketAnalyticsConfiguration    | Unsupported             |


#### CORS

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

| Method                             | Status                     |
| ---------------------------------- | -----------------------    |
| GetBucketNotification              | Unsupported                |
| GetBucketNotificationConfiguration | Unsupported                |
| ListenBucketNotification           | Unsupported, non-standard? |
| PutBucketNotification              | Unsupported                |
| PutBucketNotificationConfiguration | Unsupported                |

#### Ownership controls

| Method                        | Status                  |
| ----------------------------- | ----------------------- |
| DeleteBucketOwnershipControls | Unsupported             |
| GetBucketOwnershipControls    | Unsupported             |
| PutBucketOwnershipControls    | Unsupported             |

#### Policy and replication

| Method                  | Status                     |
| ----------------------- | -----------------------    |
| DeleteBucketPolicy      | Unsupported                |
| DeleteBucketReplication | Unsupported                |
| DeletePublicAccessBlock | Unsupported                |
| GetBucketPolicy         | Supported                  |
| GetBucketPolicyStatus   | Unsupported                |
| GetBucketReplication    | Unsupported                |
| PostPolicyBucket        | Unsupported, non-standard? |
| PutBucketPolicy         | Supported                  |
| PutBucketReplication    | Unsupported                |

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
