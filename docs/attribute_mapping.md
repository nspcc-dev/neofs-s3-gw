# Attributes

Each uploaded object includes a set of attributes.

## Common Attributes

### `S3-versioning-state`

If bucket versioning is enabled, each uploaded object will have the attribute `S3-versioning-state: Enabled`.
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

### `S3-delete-marker`

Contains the server timestamp of object removal for versioned container. It is used for special object called
`delete marker`.
A delete marker is a marker for a versioned object that was specified in a simple DELETE request.
GET request for a delete marker doesn't retrieve anything because a delete marker has no data.
GET request doesn't specify a `versionId` get a 404 (Not Found) error.

More details in the [AWS Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html).

---

## Multipart Uploads

### Multipart Info Object

This object is required for listing multipart uploads. [AWS Documentation](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-multipart-uploads.html)

Includes the following attributes:

- `s3MetaMultipartType: info`
- `s3mpObjectKey`
- `s3mpUpload`
- `s3mpMeta`, contains base64 encoded map with: `s3mpObjectKey`, `s3mpOwner`, `s3mpCreated`, `s3mpCopiesNumber`

### Multipart Part Object

This object is required for listing part for multipart upload. [AWS Documentation](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-multipart-uploads.html)
It also required to complete multipart upload. 

Includes the following attributes:

- `s3MetaMultipartType: part`
- `s3mpPartNumber`
- `s3mpElementId`
- `s3mpTotalSize`
- `s3mpHash`
- `s3mpHomoHash`
- `s3mpIsArbitrary`
- `s3mpUpload`

---

The following attributes are used in the context of multipart upload logic.

### `s3MetaMultipartType`

Indicates the type of object within a multipart upload.

**Possible values:**

- `info` – Stores multipart upload metadata
- `part` – Stores information about an individual part

### `s3mpPartNumber`

Stores the part number for multipart uploads.  
Note: Per [AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html), the first valid
part number is `1`.  
An internal part `0` exist but is hidden from users.

### `s3mpElementId`

Since each part can be up to 5 GB (and NeoFS atomic max object size smaller), this attribute tracks internal slices that
form a full part.

### `s3mpTotalSize`

Describes the total size of all sliced elements that comprise a part.

### `s3mpHash`

Stores the intermediate hash state used to compute the final object hash.

### `s3mpHomoHash`

Stores the intermediate state for computing a homomorphic hash, if enabled.

### `s3mpIsArbitrary`

Indicates whether a part was uploaded out of sequence.

**Possible values:**

- `true`

**Example:**

- Upload part 1
- Upload part 3 → This will be marked with `s3mpIsArbitrary: true` because part 2 is missing.

### `s3mpObjectKey`

Represents the object key for the multipart upload.  
This is stored separately from the `object.AttributeFilePath` attribute and ensures that multipart-uploaded object
remain inaccessible
to users until `CompleteMultipartUpload` is called.

### `s3mpUpload`

Stores the multipart upload ID.

### `s3mpPartHash`

Stores the hash of the entire part (including slices).

### `s3mpOwner`

Stores the owner of the uploading object.

### `s3mpCopiesNumber`

Indicates the CopiesNumber setting for the object.

### `s3mpMeta`

Contains the original object's attributes.

### `s3mpCreated`

Contains the final creation timestamp of the object.

### `s3bsVersioning`

Indicates whether bucket versioning is enabled.

### `.s3-object-version`

If bucket versioning is enabled, this attribute indicates which version the object belongs to.

### `.s3-compliance-mode`

Indicates whether the object is under a compliance-mode retention lock.

**Possible values:**

- `true`

### `.s3-retention-until`

Contains the retention expiration timestamp in `time.RFC3339` format.

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

---

### `s3MetaType`

Describes special metadata types used for S3 features.

**Possible values:**

- `lock` – Stores object lock info
- `tags` – Stores object tags
- `bucketTags` – Stores bucket tags
- `bucketNotifConf` – Stores bucket notification configuration
- `bucketCORS` – Stores bucket CORS configuration
- `bucketSettings` – Stores bucket settings

---

## Special Meta Objects

These objects are used to implement specific S3 features.

### Lock Object

Stores lock data for an object.

**Attributes:**

- `s3MetaType: lock`
- `.s3-object-version`
- `S3-versioning-state`

### Tags Object

Stores tag data for an object.

**Attributes:**

- `s3MetaType: tags`
- `.s3-object-version`
- `S3-versioning-state`

### Bucket Tags Object

Stores tag data for a bucket.

**Attributes:**

- `s3MetaType: bucketTags`

### Bucket Notifications Object

Stores bucket notification configuration.

**Attributes:**

- `s3MetaType: bucketNotifConf`

The object payload contains the configuration data.

[Format](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration.html)
> Note `QueueConfigurations` only supported.

### Bucket CORS Object

Stores bucket CORS configuration.

**Attributes:**

- `s3MetaType: bucketCORS`

The object payload contains the configuration data in XML format.
[Format](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ManageCorsUsing.html)

### Bucket Settings Object

Stores settings configuration for a bucket.

**Attributes:**

- `s3MetaType: bucketSettings`
- `s3bsVersioning`

The object payload contains the settings data.

It canbe empty string or `%s,%d,%s,%d` string.

* `string`. Is object lock enabled. Possible values: `` (empty string), `Enabled`.
* `int64`. Retention days for bucket objects.
* `string`. Retention mode. Possible values: `GOVERNANCE`, `COMPLIANCE`.
* `int64`. Retention years for bucket objects.

`Days` and `Years` represent durations and cannot be used simultaneously. Only one of them can be specified at a time.
