# Attributes

Each uploaded object includes a set of attributes.

## Common Attributes

### `S3-versioning-state`

If bucket versioning is enabled, each uploaded object will have the attribute `S3-versioning-state: Enabled`.
If bucket versioning is disabled, this attribute will not be present.

**Possible values:**

- `Enabled`

### `__NEOFS__NONCE`

Used when multiple objects with the same name are uploaded within the same second.
Without this attribute, the objects would share identical IDs.

### `Timestamp`

A NeoFS SDK attribute containing the UNIX timestamp of object creation.

### `FilePath`

A NeoFS SDK attribute representing the object name. This is used by end-users to interact with the gateway.

### `S3-delete-marker`

Contains the server timestamp of object removal.  
More details in the [AWS Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html).

---

## Multipart Uploads

### Multipart Info Object

Includes the following attributes:

- `s3MetaMultipartType: info`
- `s3mpObjectKey`
- `s3mpUpload`
- `s3mpMeta`, contains base64 encoded map with: `s3mpObjectKey`, `s3mpOwner`, `s3mpCreated`, `s3mpCopiesNumber`

### Multipart Part Object

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
This is stored separately from the `object.AttributeFilePath` attribute and ensures that multipart-uploaded object remain inaccessible
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

Contains encryption algorith for object payload, if enctiption is enabled.

### S3-Decrypted-Size

Contains decrypted size for object payload, if enctiption is enabled.

### S3-HMAC-Salt

Contains salt for encryption algorith, if enctiption is enabled.

### S3-HMAC-Key

Contains key for encryption algorith, if enctiption is enabled.

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

### Bucket CORS Object

Stores bucket CORS configuration.

**Attributes:**

- `s3MetaType: bucketCORS`

The object payload contains the configuration data.

### Bucket Settings Object

Stores settings configuration for a bucket.

**Attributes:**

- `s3MetaType: bucketSettings`
- `s3bsVersioning`

The object payload contains the settings data.
