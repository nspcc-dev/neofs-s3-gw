# S3 API support

Reference:
* [AWS S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/s3-api.pdf)

|    | Legend                                    |
|----|-------------------------------------------|
| 🟢 | Supported                                 |
| 🟡 | Partially supported                       |
| 🔵 | Not supported yet, but will be in future  |
| 🔴 | Not applicable or will never be supported |

## Object

|    | Method                 | Comments                                |
|----|------------------------|-----------------------------------------|
| 🟢 | CopyObject             | Done on gateway side                    |
| 🟢 | DeleteObject           |                                         |
| 🟢 | DeleteObjects          | aka DeleteMultipleObjects               |
| 🟢 | GetObject              |                                         |
| 🔴 | GetObjectTorrent       | We don't plan implementing BT gateway   |
| 🟢 | HeadObject             |                                         |
| 🟢 | ListParts              | Parts loaded with MultipartUpload       |
| 🟢 | ListObjects            |                                         |
| 🟢 | ListObjectsV2          |                                         |
| 🟢 | PutObject              | Content-MD5 header deprecated           |
| 🔵 | SelectObjectContent    | Need to have some Lambda to execute SQL |
| 🔵 | WriteGetObjectResponse | Waiting for Lambda to be developed      |
| 🟢 | GetObjectAttributes    |                                         |

* DeleteObjects limited by max amount of objects which can be deleted per request. See `max_object_to_delete_per_request` parameter.
* For calculating object ETag, we use SHA256 hash instead of MD5. 
* PutObject into a container with public-write permissions as an anonymous user (for instance, with CLI option --no-sign-request) is impossible, if try to set custom ACL for the object. It happens because container ACL rules may be changed only by container owner.

## ACL

For now there are some limitations:
* [Bucket policy](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html) supports only one `Principal` per `Statement`. 
Principal must be `"AWS": "*"` (to refer all users) or `"CanonicalUser": "0313b1ac3a8076e155a7e797b24f0b650cccad5941ea59d7cfd51a024a8b2a06bf"` (hex encoded public key of desired user).
* Resource in bucket policy is an array. Each item MUST contain bucket name, CAN contain object name (wildcards are not supported):
```json
{
  "Statement": [
    {
      "Resource": [
        "arn:aws:s3:::bucket",
        "arn:aws:s3:::bucket/some/object"
      ]
    }
  ]
}
```
* AWS conditions and wildcard are not supported in [resources](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html)
* Only `CanonicalUser` (with hex encoded public key) and `All Users Group` are supported in [ACL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html).
`Authenticated Users group` is not supported. It is a part of `All Users Group` and can't be separated from it.

|    | Method       | Comments        |
|----|--------------|-----------------|
| 🟡 | GetObjectAcl | See Limitations |
| 🟡 | PutObjectAcl | See Limitations |

## Locking

For now there are some limitations:
* Retention period can't be shortened, only extended.
* You can't delete locks or object with unexpired lock. This means PutObjectLegalHold with OFF status raise Unsupported error.

|     | Method                     | Comments                  |
|-----|----------------------------|---------------------------|
| 🟡  | GetObjectLegalHold         |                           |
| 🟢  | GetObjectLockConfiguration | GetBucketObjectLockConfig |
| 🟡  | GetObjectRetention         |                           |
| 🟡  | PutObjectLegalHold         |                           |
| 🟢  | PutObjectLockConfiguration | PutBucketObjectLockConfig |
| 🟡  | PutObjectRetention         |                           |

## Multipart

Should be supported soon.

|    | Method                  | Comments |
|----|-------------------------|----------|
| 🟢 | AbortMultipartUpload    |          |
| 🟢 | CompleteMultipartUpload |          |
| 🟢 | CreateMultipartUpload   |          |
| 🟢 | ListMultipartUploads    |          |
| 🟢 | ListParts               |          |
| 🟢 | UploadPart              |          |
| 🟢 | UploadPartCopy          |          |

## Tagging

|    | Method              | Comments |
|----|---------------------|----------|
| 🟢 | DeleteObjectTagging |          |
| 🟢 | GetObjectTagging    |          |
| 🟢 | PutObjectTagging    |          |

## Versioning

See also `GetObject` and other method parameters.

|    | Method             | Comments                 |
|----|--------------------|--------------------------|
| 🟢 | ListObjectVersions | ListBucketObjectVersions |
| 🔵 | RestoreObject      |                          |

## Bucket

|    | Method               | Comments  |
|----|----------------------|-----------|
| 🟢 | CreateBucket         | PutBucket |
| 🟢 | DeleteBucket         |           |
| 🟢 | GetBucketLocation    |           |
| 🟢 | HeadBucket           |           |
| 🟢 | ListBuckets          |           |
| 🔵 | PutPublicAccessBlock |           |

## Acceleration

|    | Method                           | Comments            |
|----|----------------------------------|---------------------|
| 🔴 | GetBucketAccelerateConfiguration | GetBucketAccelerate |
| 🔴 | PutBucketAccelerateConfiguration |                     |

## ACL

|    | Method       | Comments            |
|----|--------------|---------------------|
| 🟡 | GetBucketAcl | See ACL limitations |
| 🟡 | PutBucketAcl | See ACL Limitations |

## Analytics

|    | Method                             | Comments |
|----|------------------------------------|----------|
| 🔵 | DeleteBucketAnalyticsConfiguration |          |
| 🔵 | GetBucketAnalyticsConfiguration    |          |
| 🔵 | ListBucketAnalyticsConfigurations  |          |
| 🔵 | PutBucketAnalyticsConfiguration    |          |

## CORS

|    | Method           | Comments |
|----|------------------|----------|
| 🟢 | DeleteBucketCors |          |
| 🟢 | GetBucketCors    |          |
| 🟢 | PutBucketCors    |          |

## Encryption

|    | Method                 | Comments |
|----|------------------------|----------|
| 🔵 | DeleteBucketEncryption |          |
| 🔵 | GetBucketEncryption    |          |
| 🔵 | PutBucketEncryption    |          |

## Inventory

|    | Method                             | Comments |
|----|------------------------------------|----------|
| 🔵 | DeleteBucketInventoryConfiguration |          |
| 🔵 | GetBucketInventoryConfiguration    |          |
| 🔵 | ListBucketInventoryConfigurations  |          |
| 🔵 | PutBucketInventoryConfiguration    |          |
     
## Lifecycle

|    | Method                          | Comments |
|----|---------------------------------|----------|
| 🔵 | DeleteBucketLifecycle           |          |
| 🔵 | GetBucketLifecycle              |          |
| 🔵 | GetBucketLifecycleConfiguration |          |
| 🔵 | PutBucketLifecycle              |          |
| 🔵 | PutBucketLifecycleConfiguration |          |

## Logging

|    | Method           | Comments |
|----|------------------|----------|
| 🔵 | GetBucketLogging |          |
| 🔵 | PutBucketLogging |          |

## Metrics

|    | Method                           | Comments |
|----|----------------------------------|----------|
| 🔵 | DeleteBucketMetricsConfiguration |          |
| 🔵 | GetBucketMetricsConfiguration    |          |
| 🔵 | ListBucketMetricsConfigurations  |          |
| 🔵 | PutBucketMetricsConfiguration    |          |

## Notifications

|    | Method                             | Comments      |
|----|------------------------------------|---------------|
| 🔵 | GetBucketNotification              |               |
| 🔵 | GetBucketNotificationConfiguration |               |
| 🔵 | ListenBucketNotification           | non-standard? |
| 🔵 | PutBucketNotification              |               |
| 🔵 | PutBucketNotificationConfiguration |               |

## Ownership controls

|    | Method                        | Comments |
|----|-------------------------------|----------|
| 🔵 | DeleteBucketOwnershipControls |          |
| 🔵 | GetBucketOwnershipControls    |          |
| 🔵 | PutBucketOwnershipControls    |          |

## Policy and replication

|    | Method                  | Comments                    |
|----|-------------------------|-----------------------------|
| 🔵 | DeleteBucketPolicy      |                             |
| 🔵 | DeleteBucketReplication |                             |
| 🔵 | DeletePublicAccessBlock |                             |
| 🟡 | GetBucketPolicy         | See ACL limitations         |
| 🔵 | GetBucketPolicyStatus   |                             |
| 🔵 | GetBucketReplication    |                             |
| 🟢 | PostPolicyBucket        | Upload file using POST form |
| 🟡 | PutBucketPolicy         | See ACL limitations         |
| 🔵 | PutBucketReplication    |                             |

## Request payment

|    | Method                  | Comments |
|----|-------------------------|----------|
| 🔴 | GetBucketRequestPayment |          |
| 🔴 | PutBucketRequestPayment |          |

## Tagging

|    | Method              | Comments |
|----|---------------------|----------|
| 🟢 | DeleteBucketTagging |          |
| 🟢 | GetBucketTagging    |          |
| 🟢 | PutBucketTagging    |          |

## Tiering

|    | Method                                      | Comments |
|----|---------------------------------------------|----------|
| 🔵 | DeleteBucketIntelligentTieringConfiguration |          |
| 🔵 | GetBucketIntelligentTieringConfiguration    |          |
| 🔵 | ListBucketIntelligentTieringConfigurations  |          |
| 🔵 | PutBucketIntelligentTieringConfiguration    |          |

## Versioning

|    | Method              | Comments |
|----|---------------------|----------|
| 🟢 | GetBucketVersioning |          |
| 🟢 | PutBucketVersioning |          |

## Website

|    | Method              | Comments |
|----|---------------------|----------|
| 🔵 | DeleteBucketWebsite |          |
| 🔵 | GetBucketWebsite    |          |
| 🔵 | PutBucketWebsite    |          |


## Metadata

Each meta parameter value must be non-empty. If any parameter value is an empty,
then "Your metadata headers are not supported." error will be returned on the object put operation.
