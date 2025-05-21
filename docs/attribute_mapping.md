# Attributes

Each uploaded object includes a set of attributes.

## Common Attributes

### `S3-Meta-VersioningState`

S3 buckets can have versioning enabled, disabled or suspended. The expected
behavior for puts/gets is dependent on combination of current _and_ previous
(at object creation time) setting, so while technically the setting is
bucket-level we need to know if the object was created with versioning enabled
or not. This attribute makes it possible.

If bucket versioning is enabled, each uploaded object will have the attribute `S3-Meta-VersioningState: Enabled`.
> It means storing multiple versions of an object within the same bucket. Each version can be retrieved from the
> versioning container. If you attempt to retrieve an object by name without specifying a version,
> the latest uploaded version will be returned.

If bucket versioning is disabled, this attribute will not be present.
> It means each object has only one visible version. When retrieving an object by name, the latest uploaded version
> is returned. In fact, every object uploaded with the same name is preserved in NeoFS, but only the most recent version
> is accessible to the user.

**Possible values:**

- `Enabled`

### `__NEOFS__NONCE`

In NeoFS, the `ObjectID` is calculated as a `SHA256` hash of the marshalled object header. The object's creation time
is stored in the `Timestamp` attribute within the header. This means that two objects with identical attributes,
created within the same second, will result in the same `ObjectID`. To ensure uniqueness, each object has
`__NEOFS__NONCE`
header, which makes each object distinct.

### `Timestamp`

A NeoFS SDK attribute containing the UNIX timestamp of object creation.

### `FilePath`

A NeoFS SDK attribute representing the object name. This is used by end-users to interact with the gateway.

### `S3-Meta-DeleteMarker`

Contains the server timestamp of object removal for versioned container. It is used for special object called
`delete marker`.
A delete marker is a marker for a versioned object that was specified in a simple DELETE request.
GET request for a delete marker doesn't retrieve anything because a delete marker has no data.
GET request doesn't specify a `versionId` get a 404 (Not Found) error.

More details in the [AWS Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html).

---

## Multipart Uploads

### Multipart Info Object

This object is required for listing multipart
uploads. [AWS Documentation](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-multipart-uploads.html)

Includes the following attributes:

- `S3-MetaType: multipartInfo`
- `S3-MP-ObjectKey`
- `S3-MP-Upload`
- `S3-MP-Meta`, contains base64 encoded map with: `S3-MP-ObjectKey`, `S3-MP-Owner`, `S3-MP-Created`,
  `S3-MP-CopiesNumber`

### Multipart Part Object

This object is required for listing part for multipart
upload. [AWS Documentation](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-multipart-uploads.html)
It also required to complete multipart upload.

Includes the following attributes:

- `S3-MetaType: multipartPart`
- `S3-MP-PartNumber`
- `S3-MP-ElementId`
- `S3-MP-TotalSize`
- `S3-MP-Hash`
- `S3-MP-HomoHash`
- `S3-MP-IsArbitrary`
- `S3-MP-Upload`

---

The following attributes are used in the context of multipart upload logic.

### `S3-MP-PartNumber`

Stores the part number for multipart uploads.  
Note: Per [AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html), the first valid
part number is `1`.  
An internal part `0` exist but is hidden from users.

### `S3-MP-ElementId`

Since each part can be up to 5 GB (and NeoFS atomic max object size smaller), this attribute tracks internal slices that
form a full part.

### `S3-MP-TotalSize`

Describes the total size of all sliced elements that comprise a part.

### `S3-MP-Hash`

Stores the intermediate hash state used to compute the final object hash.

### `S3-MP-HomoHash`

Stores the intermediate state for computing a homomorphic hash, if enabled.

### `S3-MP-IsArbitrary`

Indicates whether a part was uploaded out of sequence.

**Possible values:**

- `true`

**Example:**

- Upload part 1
- Upload part 3 → This will be marked with `S3-MP-IsArbitrary: true` because part 2 is missing.

### `S3-MP-ObjectKey`

Represents the object key for the multipart upload.  
This is stored separately from the `object.AttributeFilePath` attribute and ensures that multipart-uploaded object
remain inaccessible
to users until `CompleteMultipartUpload` is called.

### `S3-MP-Upload`

Stores the multipart upload ID.

### `S3-MP-PartHash`

Stores the hash of the entire part (including slices).

### `S3-MP-Owner`

Stores the owner of the uploading object.

### `S3-MP-CopiesNumber`

Indicates the CopiesNumber setting for the object.

### `S3-MP-Meta`

Contains the original object's attributes.

### `S3-MP-Created`

Contains the final creation timestamp of the object.

### `S3-BucketSettings-Versioning`

Indicates whether bucket versioning is enabled.

### `S3-BucketSettings-MetaVersion`

Specifies the version of the bucket settings object's file structure

### `S3-ObjectVersion`

If bucket versioning is enabled, this attribute indicates which version the object belongs to.

### `S3-Lock-Meta`

Contains JSON encoded lock metadata in the next fields:
- `ComplianceMode`. Indicates whether the object is under a compliance-mode retention lock.
- `RetentionUntil`. Contains the retention expiration timestamp.

### S3-Algorithm

Contains encryption algorith for object payload, if encryption is enabled.

### S3-Decrypted-Size

Contains decrypted size for object payload, if encryption is enabled.

### S3-HMAC-Salt

Contains salt for encryption algorith, if encryption is enabled.

### S3-HMAC-Key

Contains key for encryption algorith, if encryption is enabled.

### S3-Completed-Parts

Contains info about all multipart parts for object. It is stored in the final object attributes.

### S3-Meta-Tag-*

Attributes with the `S3-Meta-Tag-` prefix contain tags for the original object. These attributes can be a part of
an original object or a tags meta object.

---

### `S3-MetaType`

Describes special metadata types used for S3 features.

**Possible values:**

- `tags` – Stores object tags
- `bucketTags` – Stores bucket tags
- `bucketNotifConf` – Stores bucket notification configuration
- `bucketCORS` – Stores bucket CORS configuration
- `bucketSettings` – Stores bucket settings
- `multipartInfo` – Stores multipart upload metadata
- `multipartPart` – Stores information about an individual part

---

## Special Meta Objects

These objects are used to implement specific S3 features.

### Lock Object

Stores lock data for an object. It has a standard NeoFS LOCK type and standard
contents for NeoFS lock objects.

**Attributes:**

- `S3-ObjectVersion`
- `S3-Meta-VersioningState`
- `S3-Lock-Meta`

### Tags Object

Stores tag data for an object. Contents is a JSON object with string keys and
values repsenting tags.

Tags passed with an object during a `Put` operation are stored as object attributes using the `S3-Meta-Tag-` prefix.
In this case, the creation of a separate metadata object is skipped. To enable proper handling of tag removal,
an empty metadata object is created during a `DeleteObjectTagging` request.

Any subsequent changes to the object's attributes will result in the creation of tag metadata objects as usual.
It stores the original object's tags within the body payload. Additionally, it uses the `S3-Meta-Tag-` prefix to store
the original object's attributes.

**Attributes:**

- `S3-MetaType: tags`
- `S3-ObjectVersion`
- `S3-Meta-VersioningState`

### Bucket Tags Object

Stores tag data for a bucket. Contents is a JSON object with string keys and
values repsenting tags.

**Attributes:**

- `S3-MetaType: bucketTags`

### Bucket Notifications Object

Stores bucket notification configuration.

**Attributes:**

- `S3-MetaType: bucketNotifConf`

The object payload contains the configuration data.

[Format](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration.html)
> Note `QueueConfigurations` only supported.

### Bucket CORS Object

Stores bucket CORS configuration.

**Attributes:**

- `S3-MetaType: bucketCORS`

The object payload contains the configuration data in XML format.
[Format](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html)

### Bucket Settings Object

Stores settings configuration for a bucket.

**Attributes:**

- `S3-MetaType: bucketSettings`
- `S3-BucketSettings-Versioning`
  Deprecated, replaced by meta version.
- `S3-BucketSettings-MetaVersion`
  Stores settings version.

The object payload contains settings data in JSON format. For version 1 it's
an object with the following fields:
 * "versioning", corresponding to bucket versioning settings
   (Unversioned/Enabled/Suspended)
 * "lock_configuration" which is an object with "ObjectLockEnabled" and "Rule"
   members corresponding to XML parameters of lock configuration in S3 API
 * "bucket_owner" which is a number representing object ownership and ACL
   settings (0 for owner enforced, 1 for owner preferred, 2 for owner
   preferred and restricted and 3 for object writer owner)
