# AWS ACL and ACP

## ACP

## ACL
Contains list of Grantees and Permissions.

### Grantee
Can be any AWS account (specified by ID or email address) or predefined group.
AWS account ID is mapped to NeoFS wallet id. Getting ID from email is outside
of scope of NeoFS node.

There are 3 groups:
1. All users. Includes all possible users. The request can be unsigned.
2. Authenticated users. Includes all users with AWS id. The request must be signed.
3. Log Delivery.

Distinction between 1 and 2 should be maintained in S3-gate.
In the following every access is accompanied and signed by some user ID
(possibly some default).

### Permissions
Permission|Bucket|Object
---|---|---
READ|List objects in the bucket|Read object data and metadata
WRITE|Create new objects in bucket|Not applicable
READ_ACP|Read the bucket ACL|Read the object ACL
WRITE_ACP|Write the bucket ACL|Write the object ACL
FULL_CONTROL|All permissions combined|All permissions combined

In NeoFS permissions are stored in ACL and extended ACL.
Basic ACL is created once and stored together with the container.
This has some implications when mapping to NeoFS:
1. Because AWS ACL can be changed we need to have some default ACL (most likely
   `ALLOW` for all requests because eACL cannot contradict basic ACL).
2. AWS ACL allows granting permissions for each object separately. This can lead
   to fast eACL increase if we store permission for each object using a single eACL rule.
3. `WRITE_ACP` permission allows writing object ACL which can possibly lead to rewriting
   eACL without having `WRITE_ACP` for bucket (container) permission.

Let's consider some examples to illustrate possible mapping. If not specified the described
situation is bucket/object owner wants to grant permission in case to some other user.
The last eACL rule is always `DENY All`.

#### Current NeoFS eacl checking pipeline:
For each record:
1. Check that operation matches request operation, otherwise go to the next record. 
2. Check that record target matches request. This is based either on group or role. 
   Otherwise, go to the next record.
3. Try to match record filters.
   1. If there is no header/request found, consider all filters as matched.
    We probably should skip in this case.
   2. ...

Let's see how other S3 ACL examples are converted:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
```xml
<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>Owner-canonical-user-ID</ID>
    <DisplayName>display-name</DisplayName>
  </Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>Owner-canonical-user-ID</ID>
        <DisplayName>display-name</DisplayName>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>user1-canonical-user-ID</ID>
        <DisplayName>display-name</DisplayName>
      </Grantee>
      <Permission>WRITE</Permission>
    </Grant>

    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
        <ID>user2-canonical-user-ID</ID>
        <DisplayName>display-name</DisplayName>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>

    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI> 
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
        <URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI>
      </Grantee>
      <Permission>WRITE</Permission>
    </Grant>

  </AccessControlList>
</AccessControlPolicy>
```
This corresponds to the following eACL (groups are not implemented yet,
assume `DENY` in basic ACL by default):

Action|Operation|Filter|Target
---|---|---|---
ALLOW|PUT|`O Object:objectID=<id>`|others:Owner-canonical-user-ID
ALLOW|PUT|`O Object:objectID=<id>`<br>`S AWS:permission=FULL_CONTROL`<br>`S AWS:owner=`|others:Owner-canonical-user-ID
ALLOW|PUT|`O Object:objectID=<id>`|others:user1-canonical-user-ID
ALLOW|PUT|`O Object:objectID=<id>`<br>`S AWS:permission=WRITE`|others:user1-canonical-user-ID
ALLOW|GET|`O Object:objectID=<id>`|others:user2-canonical-user-ID
ALLOW|GET|`O Object:objectID=<id>`<br>`S AWS:permission=READ`|others:user2-canonical-user-ID
ALLOW|GET|`O Object:objectID=<id>`|unknown
ALLOW|GET|`O Object:objectID=<id>`<br>`S AWS:permission=READ`<br>`S AWS:group=AllUsers`|unknown
ALLOW|PUT|`O Object:objectID=<id>`|unknown
ALLOW|PUT|`O Object:objectID=<id>`<br>`S AWS:permission=WRITE`<br>`S AWS:group=LogDelivery`|unknown