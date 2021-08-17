# S3 API support

Reference:
* [AWS S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/s3-api.pdf)

|    | Legend                                    |
|----|-------------------------------------------|
| 🟢 | Supported                                 |
| 🟡 | Partially supported                       |
| 🔴 | Not supported yet, but will be in future  |
| 🔵 | Not applicable or will never be supported |

## Object

|    | Method                 | Comments                                |
|----|------------------------|-----------------------------------------|
| 🟢 | CopyObject             | Done on gateway side                    |
| 🟢 | DeleteObject           |                                         |
| 🟢 | DeleteObjects          | aka DeleteMultipleObjects               |
| 🟢 | GetObject              |                                         |
| 🔵 | GetObjectTorrent       | We don't plan implementing BT gateway   |
| 🟢 | HeadObject             |                                         |
| 🔴 | ListObjectParts        |                                         |
| 🟢 | ListObjects            |                                         |
| 🟢 | ListObjectsV2          |                                         |
| 🟢 | PutObject              | Content-MD5 header deprecated           |
| 🔴 | SelectObjectContent    | Need to have some Lambda to execute SQL |
| 🔴 | WriteGetObjectResponse | Waiting for Lambda to be developed      |

## ACL

For now there are some limitations:
* [Bucket policy](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html) support only one `Principal` (type `AWS`) per `Statement`. To refer all users use `"AWS": "*"`
* AWS conditions and wildcard are not supported in [resources](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html)
* Only `CanonicalUser` (with hex encoded public key) and `All Users Group` are supported in [ACL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)

|    | Method       | Comments        |
|----|--------------|-----------------|
| 🟡 | GetObjectAcl | See Limitations |
| 🟡 | PutObjectAcl | See Limitations |

## Locking

|    | Method                     | Comments                  |
|----|----------------------------|---------------------------|
| 🔴 | GetObjectLegalHold         |                           |
| 🔴 | GetObjectLockConfiguration | GetBucketObjectLockConfig |
| 🔴 | GetObjectRetention         |                           |
| 🔴 | PutObjectLegalHold         |                           |
| 🔴 | PutObjectLockConfiguration | PutBucketObjectLockConfig |
| 🔴 | PutObjectRetention         |                           |

## Multipart

Should be supported soon.

|    | Method                  | Comments                                       |
|----|-------------------------|------------------------------------------------|
| 🔴 | AbortMultipartUpload    |                                                |
| 🔴 | CompleteMultipartUpload |                                                |
| 🔴 | CreateMultipartUpload   | InitiateMultipartUpload and NewMultipartUpload |
| 🔴 | ListMultipartUploads    |                                                |
| 🔴 | ListParts               |                                                |
| 🔴 | UploadPart              | PutObjectPart                                  |
| 🔴 | UploadPartCopy          | CopyObjectPart                                 |

## Tagging

|    | Method              | Comments |
|----|---------------------|----------|
| 🔴 | DeleteObjectTagging |          |
| 🔴 | GetObjectTagging    |          |
| 🟢 | PutObjectTagging    |          |

## Versioning

See also `GetObject` and other method parameters.

|    | Method             | Comments                 |
|----|--------------------|--------------------------|
| 🟢 | ListObjectVersions | ListBucketObjectVersions |
| 🔴 | RestoreObject      |                          |

## Bucket

|    | Method               | Comments  |
|----|----------------------|-----------|
| 🟢 | CreateBucket         | PutBucket |
| 🟢 | DeleteBucket         |           |
| 🔴 | GetBucketLocation    |           |
| 🟢 | HeadBucket           |           |
| 🟢 | ListBuckets          |           |
| 🔴 | PutPublicAccessBlock |           |

## Acceleration

|    | Method                           | Comments            |
|----|----------------------------------|---------------------|
| 🔵 | GetBucketAccelerateConfiguration | GetBucketAccelerate |
| 🔵 | PutBucketAccelerateConfiguration |                     |

## ACL

|    | Method       | Comments  |
|----|--------------|-----------|
| 🟢 | GetBucketAcl | Supported |
| 🟢 | PutBucketAcl | Supported |

## Analytics

|    | Method                             | Comments |
|----|------------------------------------|----------|
| 🔴 | DeleteBucketAnalyticsConfiguration |          |
| 🔴 | GetBucketAnalyticsConfiguration    |          |
| 🔴 | ListBucketAnalyticsConfigurations  |          |
| 🔴 | PutBucketAnalyticsConfiguration    |          |

## CORS

|    | Method           | Comments |
|----|------------------|----------|
| 🔴 | DeleteBucketCors |          |
| 🔴 | GetBucketCors    |          |
| 🔴 | PutBucketCors    |          |

## Encryption

|    | Method                 | Comments |
|----|------------------------|----------|
| 🔴 | DeleteBucketEncryption |          |
| 🔴 | GetBucketEncryption    |          |
| 🔴 | PutBucketEncryption    |          |

## Inventory

|    | Method                             | Comments |
|----|------------------------------------|----------|
| 🔴 | DeleteBucketInventoryConfiguration |          |
| 🔴 | GetBucketInventoryConfiguration    |          |
| 🔴 | ListBucketInventoryConfigurations  |          |
| 🔴 | PutBucketInventoryConfiguration    |          |
     
## Lifecycle

|    | Method                          | Comments |
|----|---------------------------------|----------|
| 🔴 | DeleteBucketLifecycle           |          |
| 🔴 | GetBucketLifecycle              |          |
| 🔴 | GetBucketLifecycleConfiguration |          |
| 🔴 | PutBucketLifecycle              |          |
| 🔴 | PutBucketLifecycleConfiguration |          |

## Logging

|    | Method           | Comments |
|----|------------------|----------|
| 🔴 | GetBucketLogging |          |
| 🔴 | PutBucketLogging |          |

## Metrics

|    | Method                           | Comments |
|----|----------------------------------|----------|
| 🔴 | DeleteBucketMetricsConfiguration |          |
| 🔴 | GetBucketMetricsConfiguration    |          |
| 🔴 | ListBucketMetricsConfigurations  |          |
| 🔴 | PutBucketMetricsConfiguration    |          |

## Notifications

|    | Method                             | Comments      |
|----|------------------------------------|---------------|
| 🔴 | GetBucketNotification              |               |
| 🔴 | GetBucketNotificationConfiguration |               |
| 🔴 | ListenBucketNotification           | non-standard? |
| 🔴 | PutBucketNotification              |               |
| 🔴 | PutBucketNotificationConfiguration |               |

## Ownership controls

|    | Method                        | Comments |
|----|-------------------------------|----------|
| 🔴 | DeleteBucketOwnershipControls |          |
| 🔴 | GetBucketOwnershipControls    |          |
| 🔴 | PutBucketOwnershipControls    |          |

## Policy and replication

|    | Method                  | Comments      |
|----|-------------------------|---------------|
| 🔴 | DeleteBucketPolicy      |               |
| 🔴 | DeleteBucketReplication |               |
| 🔴 | DeletePublicAccessBlock |               |
| 🟢 | GetBucketPolicy         |               |
| 🔴 | GetBucketPolicyStatus   |               |
| 🔴 | GetBucketReplication    |               |
| 🔴 | PostPolicyBucket        | non-standard? |
| 🟢 | PutBucketPolicy         |               |
| 🔴 | PutBucketReplication    |               |

## Request payment

|    | Method                  | Comments |
|----|-------------------------|----------|
| 🔵 | GetBucketRequestPayment |          |
| 🔵 | PutBucketRequestPayment |          |

## Tagging

|    | Method              | Comments |
|----|---------------------|----------|
| 🔴 | DeleteBucketTagging |          |
| 🔴 | GetBucketTagging    |          |
| 🔴 | PutBucketTagging    |          |

## Tiering

|    | Method                                      | Comments |
|----|---------------------------------------------|----------|
| 🔴 | DeleteBucketIntelligentTieringConfiguration |          |
| 🔴 | GetBucketIntelligentTieringConfiguration    |          |
| 🔴 | ListBucketIntelligentTieringConfigurations  |          |
| 🟢 | PutBucketIntelligentTieringConfiguration    |          |

## Versioning

|    | Method              | Comments |
|----|---------------------|----------|
| 🟢 | GetBucketVersioning |          |
| 🟢 | PutBucketVersioning |          |

## Website

|    | Method              | Comments |
|----|---------------------|----------|
| 🔴 | DeleteBucketWebsite |          |
| 🔴 | GetBucketWebsite    |          |
| 🔴 | PutBucketWebsite    |          |
