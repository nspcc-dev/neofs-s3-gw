## Intro

NeoFS S3 Gate is largely based on [MinIO]("https://min.io") codebase and therefore inherits its basic API, except cases where NeoFS functionality fails to be mapped reasonably.

## Reference Resources

* [MinIO SDK Client Reference]("https://docs.min.io/docs/golang-client-api-reference.html")

* [AWS S3 API Reference]("https://docs.aws.amazon.com/AmazonS3/latest/API/s3-api.pdf")


### Bucket/Object-Level Actions

| #   | Method Name               | Status                  |
|:---:| ------------------------- | ----------------------- |
| 1   | AbortMultipartUpload      | Unsupported             |
| 2   | CompleteMultipartUpload   | Unsupported             |
| 3   | CopyObject                | Supported               |
| 4   | CopyObjectPart            | Unsupported             |
| 5   | DeleteBucket              | Unsupported             |
| 6   | DeleteBucketEncryption    | Unsupported             |
| 7   | DeleteBucketLifecycle     | Unsupported             |
| 8   | DeleteBucketPolicy        | Unsupported             |
| 9   | DeleteBucketTagging       | Unsupported             |
| 10  | DeleteBucketWebsite       | Unsupported             |
| 11  | DeleteMultipleObjects     | Unsupported (issue #26) |
| 12  | DeleteObject              | Supported               |
| 13  | DeleteObjectTagging       | Unsupported             |
| 14  | GetBucketACL              | Unsupported             |
| 15  | GetBucketAccelerate       | Supported               |
| 16  | GetBucketCors             | Unsupported             |
| 17  | GetBucketEncryption       | Unsupported             |
| 18  | GetBucketLifecycle        | Unsupported             |
| 19  | GetBucketLocation         | Unsupported             |
| 20  | GetBucketLogging          | Unsupported             |
| 21  | GetBucketNotification     | Unsupported             |
| 22  | GetBucketObjectLockConfig | Unsupported             |
| 23  | GetBucketPolicy           | Unsupported             |
| 24  | GetBucketReplication      | Unsupported             |
| 25  | GetBucketRequestPayment   | Unsupported             |
| 26  | GetBucketTagging          | Unsupported             |
| 27  | GetBucketVersioning       | Unsupported             |
| 28  | GetBucketWebsite          | Unsupported             |
| 29  | GetObject                 | Supported               |
| 30  | GetObjectACL              | Unsupported             |
| 31  | GetObjectLegalHold        | Unsupported             |
| 32  | GetObjectRetention        | Unsupported             |
| 33  | HeadBucket                | Unsupported (isuue #XX) |
| 34  | HeadObject                | Supported               |
| 35  | ListBucketObjectVersions  | Unsupported             |
| 36  | ListBuckets               | Supported               |
| 37  | ListMultipartUploads      | Unsupported             |
| 38  | ListObjectParts           | Unsupported             |
| 39  | ListObjectsV1             | Supported               |
| 40  | ListObjectsV2             | Supported               |
| 41  | ListenBucketNotification  | Unsupported             |
| 42  | NewMultipartUpload        | Unsupported             |
| 43  | PostPolicyBucket          | Unsupported             |
| 44  | PutBucket                 | Unsupported             |
| 45  | PutBucketACL              | Unsupported             |
| 46  | PutBucketEncryption       | Unsupported             |
| 47  | PutBucketLifecycle        | Unsupported             |
| 48  | PutBucketNotification     | Unsupported             |
| 49  | PutBucketObjectLockConfig | Unsupported             |
| 50  | PutBucketPolicy           | Unsupported             |
| 51  | PutBucketTagging          | Unsupported             |
| 52  | PutBucketVersioning       | Unsupported             |
| 53  | PutObject                 | Supported               |
| 54  | PutObjectACL              | Unsupported             |
| 55  | PutObjectLegalHold        | Unsupported             |
| 56  | PutObjectPart             | Unsupported             |
| 57  | PutObjectRetention        | Unsupported             |
| 58  | PutObjectTagging          | Unsupported             |
| 59  | SelectObjectContent       | Unsupported             |

