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
* Header `X-Amz-Meta-Neofs-Copies-Number` can be used with `PutObject`, `CopyObject`, `CreateMultipartUpload` methods to set object copies number. Otherwise, the default value from config will be used. See [neofs section](https://github.com/nspcc-dev/neofs-s3-gw/blob/master/docs/configuration.md#neofs-section) for more details.
    * Use metadata `neofs-copies-number` parameter for aws CLI. For instance:
    ```shell
    aws s3api put-object --endpoint $S3HOST --bucket $BUCKET --key $OBJECT_KEY --body /path/to/file.txt --metadata neofs-copies-number=3
    ```
      
## ACL

For now there are some limitations:
* [Bucket policy](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html) supports only one `Principal` per `Statement`. 
Principal must be `"AWS": "*"` or `"*"` (to refer all users) or `"CanonicalUser": "NiskPF9pfRMzg7V7PeB4d6ogLzu74a1L2Q"` (base58 encoded address of desired user).
```json
{
  "Statement": [
    {
      "Principal": "*"
    }
  ]
}
```
```json
{
  "Statement": [
    {
      "Principal": {
        "AWS": "*"
      }
    }
  ]
}
```
* Resource in bucket policy is a string value or array of strings. Each item MUST contain bucket name, CAN contain object name (wildcards are not supported):
```json
{
  "Statement": [
    {
      "Resource": "arn:aws:s3:::bucket"
    }
  ]
}
```
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
* Action is a string value or array of strings:
```json
{
  "Statement": [
    {
      "Action": "s3:PutObject"
    }
  ]
}
```
```json
{
  "Statement": [
    {
      "Action": ["s3:PutObject", "s3:PutObjectAcl"]
    }
  ]
}
```
* AWS conditions and wildcard are not supported in [resources](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-arn-format.html)
* Only `CanonicalUser` (with hex encoded public key) and `All Users Group` are supported in [ACL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html).
`Authenticated Users group` is not supported. It is a part of `All Users Group` and can't be separated from it.
* It is not possible to remove GRANTS from container owner. Using PutObjectAcl with empty grants has no effect to GRANTS for container owner, despite method completes without error.
```json
{
    "Owner": {"DisplayName": "NiskPF9pfRMzg7V7PeB4d6ogLzu74a1L2Q","ID": "NiskPF9pfRMzg7V7PeB4d6ogLzu74a1L2Q"},
    "Grants": []
}
```

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
| 🔵 | GetPublicAccessBlock |           |

* `CreateBucket` method allows you to select a placement policy using the `LocationConstraint` parameter in the AWS CLI. The policy name should be passed as a value.
  * Policies mapping can be defined via:
    * [Authmate](./authmate.md#containers-policy) during bucket creation. These policies are available only for generated credentials.
    * [Gate configuration](./configuration.md#placement_policy-section). These policies are shared and available for all gate clients.
  * Example: aws s3api create-bucket --bucket $BUCKET --endpoint $S3HOST --create-bucket-configuration LocationConstraint=$POLICY_NAME

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

Bucket ACLs are disabled, by default. See details [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html).
See [Ownership](./aws_s3_compat.md#ownership-controls) section for details.

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

Methods below are related to AWS SSE-S3 and SSE-KMS encryption. S3 gateway supports SSE-C only for now.

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

|    | Method                          | Comments                                             |
|----|---------------------------------|------------------------------------------------------|
| 🔵 | DeleteBucketLifecycle           |                                                      |
| 🟡 | GetBucketLifecycle              | It always returns NoSuchLifecycleConfiguration error |
| 🔵 | GetBucketLifecycleConfiguration |                                                      |
| 🔵 | PutBucketLifecycle              |                                                      |
| 🔵 | PutBucketLifecycleConfiguration |                                                      |

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
| 🟢 | DeleteBucketOwnershipControls |          |
| 🟢 | GetBucketOwnershipControls    |          |
| 🟢 | PutBucketOwnershipControls    |          |

In case you need to disable ACLs manually (for instance your bucket has ACLs enabled) you should use `PutBucketOwnershipControls` command:
```shell
$ aws s3api put-bucket-ownership-controls --endpoint $S3HOST --bucket $BUCKET --ownership-controls "Rules=[{ObjectOwnership=BucketOwnerEnforced}]"
```

Switch to `Preferred` mode with the next command:
```shell
$ aws s3api put-bucket-ownership-controls --endpoint $S3HOST --bucket $BUCKET --ownership-controls "Rules=[{ObjectOwnership=BucketOwnerPreferred}]"
```

Switch to `ObjectWriter` mode with the next command:
```shell
$ aws s3api put-bucket-ownership-controls --endpoint $S3HOST --bucket $BUCKET --ownership-controls "Rules=[{ObjectOwnership=ObjectWriter}]"
```

Note: `ObjectWriter` mode means fully enabled ACL.
Pay attention to the fact that object owner in NeoFS is bucket owner in any case.

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

You may set requiring the `bucket-owner-full-control` canned ACL for Amazon S3 PUT operations ([bucket owner preferred](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ensure-object-ownership.html#ensure-object-ownership-bucket-policy)):
```shell
$ aws s3api put-bucket-policy --endpoint $S3HOST --bucket $BUCKET --policy file://policy.json
```

policy.json:

> Note that S3 gate supports only `wildcard` for `Principal` parameter see [ACL section](aws_s3_compat.md#acl) for
> details.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Only allow writes to my bucket with bucket owner full control",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::$BUCKET/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

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
