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
| 🟢 | PutObject              | Content-MD5 header is checked, not kept |
| 🔵 | SelectObjectContent    | Need to have some Lambda to execute SQL |
| 🔵 | WriteGetObjectResponse | Waiting for Lambda to be developed      |
| 🟢 | GetObjectAttributes    |                                         |

* DeleteObjects limited by max amount of objects which can be deleted per request. See `max_object_to_delete_per_request` parameter.
* For calculating object ETag, we use SHA256 hash instead of MD5. 

## ACL

Object-level ACLs are not supported. `GetObjectAcl` always returns "private" (owner `FULL_CONTROL`).
`PutObjectAcl` accepts only `private` canned ACL as a no-op; any other value is rejected with `AccessControlListNotSupported`.
ACL headers on object upload requests (`PutObject`, `PostObject`, `CopyObject`, `CreateMultipartUpload`) are silently accepted as no-ops.

There are some limitations:
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
* Resource in bucket policy is a string value or array of strings. Each item MUST contain bucket name, CAN contain object name. `bucket/*` is the same as `bucket`,
any other wildcard is rejected with `422 UnsupportedPolicy`. Statements for an object take precedence over the ones for
the bucket, so `Deny` for `bucket` or `bucket/*` does not revoke `Allow` given for `bucket/object`:
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
* Supported actions are `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`, `s3:GetObjectTagging`,
`s3:PutObjectTagging` and the `s3:*` and `*` wildcards. Any other action is ignored in `Allow` statements and
rejected with `422 UnsupportedPolicy` in `Deny` ones. Within one policy, `Deny` wins if the same grantee is both allowed and denied on the same resource.
* `Effect` must be exactly `Allow` or `Deny`, anything else is rejected with `400 MalformedPolicy`
* Policy statements with `Condition` (except exactly the `bucket-owner-full-control` one described in
[Policy and replication](#policy-and-replication)), `NotPrincipal`, `NotAction` or `NotResource`
are rejected with `422 UnsupportedPolicy`
* Only `CanonicalUser` (with hex encoded public key) and `All Users Group` are supported in [ACL](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html).
`Authenticated Users group` is not supported. It is a part of `All Users Group` and can't be separated from it.

|    | Method       | Comments                                                        |
|----|--------------|-----------------------------------------------------------------|
| 🟡 | GetObjectAcl | Always returns "private" (owner FULL_CONTROL)                   |
| 🟡 | PutObjectAcl | Only `private` canned ACL accepted; others are rejected         |

## Locking

For now there are some limitations:
* Retention period can't be shortened, only extended.
* You can't delete locks or object with unexpired lock.
* Legal hold can't be set: PutObjectLegalHold and `X-Amz-Object-Lock-Legal-Hold: ON` header raise Unsupported error.

|    | Method                     | Comments                  |
|----|----------------------------|---------------------------|
| 🟡 | GetObjectLegalHold         |                           |
| 🟢 | GetObjectLockConfiguration | GetBucketObjectLockConfig |
| 🟡 | GetObjectRetention         |                           |
| 🔴 | PutObjectLegalHold         |                           |
| 🟢 | PutObjectLockConfiguration | PutBucketObjectLockConfig |
| 🟡 | PutObjectRetention         |                           |

## Multipart

|    | Method                  | Comments                  |
|----|-------------------------|---------------------------|
| 🟢 | AbortMultipartUpload    |                           |
| 🟢 | CompleteMultipartUpload |                           |
| 🟢 | CreateMultipartUpload   |                           |
| 🟢 | ListMultipartUploads    |                           |
| 🟢 | ListParts               |                           |
| 🟢 | UploadPart              | Part size, 5 MiB to 4 GiB |
| 🟢 | UploadPartCopy          | Part size, 5 MiB to 4 GiB |
  
**UploadPart**, **UploadPartCopy**

According to [S3 multipart upload limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html), the part size
must be in the 5 MiB to 5 GiB range. The gate has an additional limitation on the maximum part size, which is 4 GiB.

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
| 🔵 | RestoreObject      | Related to lifecycles and tiering. |

In some cases `ListObjectVersions` may return fewer elements than `max-keys` requested.

## Bucket

|    | Method               | Comments  |
|----|----------------------|-----------|
| 🟢 | CreateBucket         | PutBucket |
| 🟢 | DeleteBucket         |           |
| 🟢 | GetBucketLocation    |           |
| 🟢 | HeadBucket           |           |
| 🟢 | ListBuckets          |           |
| 🔵 | PutPublicAccessBlock |           |
| 🔵 | GetPublicAccessBlock | Related to ACL management, not a priority. |

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

|    | Method       | Comments                                                        |
|----|--------------|-----------------------------------------------------------------|
| 🟡 | GetBucketAcl | See ACL limitations                                             |
| 🟡 | PutBucketAcl | See ACL limitations                                             |

Bucket ACLs are disabled, by default. See details [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html).
See [Ownership](./aws_s3_compat.md#ownership-controls) section for details.

## Analytics

Requires a separate entity to generate/upload data daily.

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

Requires a separate entity to generate/upload data regularly.

|    | Method                             | Comments |
|----|------------------------------------|----------|
| 🔵 | DeleteBucketInventoryConfiguration |          |
| 🔵 | GetBucketInventoryConfiguration    |          |
| 🔵 | ListBucketInventoryConfigurations  |          |
| 🔵 | PutBucketInventoryConfiguration    |          |
     
## Lifecycle

In general requires a separate entity to manage uploaded objects. Without it
can be only partially supported.

|    | Method                          | Comments                                             |
|----|---------------------------------|------------------------------------------------------|
| 🔵 | DeleteBucketLifecycle           |                                                      |
| 🟡 | GetBucketLifecycle              | It always returns NoSuchLifecycleConfiguration error |
| 🔵 | GetBucketLifecycleConfiguration |                                                      |
| 🔵 | PutBucketLifecycle              |                                                      |
| 🔵 | PutBucketLifecycleConfiguration |                                                      |

## Logging

Doesn't make much sense in non-AWS case.

|    | Method           | Comments |
|----|------------------|----------|
| 🔵 | GetBucketLogging |          |
| 🔵 | PutBucketLogging |          |

## Metrics

Doesn't make much sense in non-AWS case.

|    | Method                           | Comments |
|----|----------------------------------|----------|
| 🔵 | DeleteBucketMetricsConfiguration |          |
| 🔵 | GetBucketMetricsConfiguration    |          |
| 🔵 | ListBucketMetricsConfigurations  |          |
| 🔵 | PutBucketMetricsConfiguration    |          |

## Notifications

Can't be exactly the same as in AWS. AMQP/NATS/etc can be supported, but it's
not exactly the gateway job. It also requires metadata synchronization.

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

Note: `ObjectWriter` mode allows passing ACL headers, but they are silently
accepted as no-ops. Object-level ACLs are not enforced.
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
| 🔵 | PutBucketReplication    | Hardly applicable to NeoFS  |

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

Tightly related to lifecycle support.

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

User metadata (`X-Amz-Meta-*` headers) with an empty value is not supported,
unlike in AWS S3, which stores such a key. Metadata is kept in NeoFS object
attributes, and an attribute can not have an empty value. A value consisting
of spaces only is empty too, because HTTP strips them.

`PutObject` and `CopyObject` with the `REPLACE` metadata directive answer such
a request with `400 InvalidArgument` ("Your metadata headers are not
supported."). `CreateMultipartUpload` fails as well. Nothing is stored in any
of these cases, the gateway never drops the key silently.

An application that needs a key without a value has to omit the key or store
some placeholder value of its own.
