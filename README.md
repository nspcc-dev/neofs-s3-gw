# NeoFS S3 Gateway

NeoFS S3 gateway provides API compatible with Amazon S3 cloud storage service.

## Installation

```go get -u github.com/nspcc-dev/neofs-s3-gw```

Or you can call `make` to build it from the cloned repository (the binary will
end up in `bin/neofs-s3-gw` with authmate helper in `bin/neofs-authmate`).

Notable make targets:

```
dep          Check and ensure dependencies
image        Build clean docker image
dirty-image  Build dirty docker image with host-built binaries
format       Run all code formatters
lint         Run linters
version      Show current version
```

Or you can also use a [Docker
image](https://hub.docker.com/r/nspccdev/neofs-s3-gw) provided for released
(and occasionally unreleased) versions of gateway (`:latest` points to the
latest stable release).

## Execution

Minimalistic S3 gateway setup needs:
 * NeoFS node(s) address (S3 gateway itself is not a NeoFS node)
   Passed via `-p` parameter or via `S3_GW_PEERS_<N>_ADDRESS` and
   `S3_GW_PEERS_<N>_WEIGHT` environment variables (gateway supports multiple
   NeoFS nodes with weighted load balancing).
 * a key used to communicate with NeoFS nodes
   Passed via `--neofs-key` parameter or `S3_GW_NEOFS-KEY` environment variable.

These two commands are functionally equivalent, they run the gate with one
backend node, some keys and otherwise default settings:
```
$ neofs-s3-gw -p 192.168.130.72:8080 --neofs-key KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr

$ S3_GW_PEERS_0_ADDRESS=192.168.130.72:8080 \
  S3_GW_NEOFS-KEY=KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr \
  neofs-s3-gw
```
It's also possible to specify uri scheme (grpc or grpcs) when using `-p` or environment variables:
```
$ neofs-s3-gw -p grpc://192.168.130.72:8080 --neofs-key KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr

$ S3_GW_PEERS_0_ADDRESS=grpcs://192.168.130.72:8080 \
  S3_GW_NEOFS-KEY=KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr \
  neofs-s3-gw
```

## Configuration

In general, everything available as CLI parameter can also be specified via
environment variables, so they're not specifically mentioned in most cases
(see `--help` also).

### Nodes and weights

You can specify multiple `-p` options to add more NeoFS nodes, this will make
gateway spread requests equally among them (using weight 1 for every node):

```
$ neofs-s3-gw -p 192.168.130.72:8080 -p 192.168.130.71:8080
```
If you want some specific load distribution proportions, use weights, but they
can only be specified via environment variables:

```
$ HTTP_GW_PEERS_0_ADDRESS=192.168.130.72:8080 HTTP_GW_PEERS_0_WEIGHT=9 \
  HTTP_GW_PEERS_1_ADDRESS=192.168.130.71:8080 HTTP_GW_PEERS_1_WEIGHT=1 neofs-s3-gw
```
This command will make gateway use 192.168.130.72 for 90% of requests and
192.168.130.71 for remaining 10%.

### Key

NeoFS (`--neofs-key`) is mandatory parameter. NeoFS key can be a path to private key file (as raw bytes), 
a hex string or (unencrypted) WIF string.

### Binding and TLS

Gateway binds to `0.0.0.0:8080` by default and you can change that with
`--listen_address` option.

It can also provide TLS interface for its users, just specify paths to key and
certificate files via `--tls.key_file` and `--tls.cert_file` parameters. Note
that using these options makes gateway TLS-only, if you need to serve both TLS
and plain text you either have to run two gateway instances or use some
external redirecting solution.

Example to bind to `192.168.130.130:443` and serve TLS there (keys and nodes
omitted):

```
$ neofs-s3-gw --listen_address 192.168.130.130:443 \
  --tls.key_file=key.pem --tls.cert_file=cert.pem
```

### Monitoring and metrics

Pprof and Prometheus are integrated into the gateway, but not enabled by
default. To enable them use `--pprof` and `--metrics` flags or
`HTTP_GW_PPROF`/`HTTP_GW_METRICS` environment variables.

## NeoFS AuthMate

Authmate is a tool to create gateway key pairs and AWS credentials. AWS users
are authenticated with access key IDs and secrets, while NeoFS users are
authenticated with key pairs. To complicate things further we have S3 gateway
that usually acts on behalf of some user, but user doesn't necessarily want to
give his keys to the gateway.

To solve this we use NeoFS bearer tokens that are signed by the owner (NeoFS
"user") and that can implement any kind of policy for NeoFS requests allowed
using this token. But tokens can't be used directly as AWS credentials, thus
they're stored on NeoFS as regular objects and access key ID is just an
address of this object while secret is an SHA256 hash of this key.

Tokens are not stored on NeoFS in plaintext, they're encrypted with a set of
gateway keys. So in order for gateway to be able to successfully extract bearer
token the object needs to be stored in a container available for the gateway
to read and it needs to be encrypted with this gateway's key (among others
potentially).

#### Generation of key pairs

To generate neofs key pairs for gateways, run the following command (`--count` is 1
by default):

```
$ ./neofs-authmate generate-keys --count=2

[
  {
    "private_key": "b8ba980eb70b959be99915d2e0ad377809984ccd1dac0a6551907f81c2b33d21",
    "public_key": "dd34f6dce9a4ce0990869ec6bd33a40e102a5798881cfe61d03a5659ceee1a64"
  },
  {
    "private_key": "407c351b17446ca07521faceb8b7d3e738319635f39f892419e2bf94462b4419",
    "public_key": "20453af9d7f245ff6fdfb1260eaa411ae3be9c519a2a9bf1c98233522cbd0156"
  }
]
```

Private key is the one to use for `neofs-s3-gw` command, public one can be
used to create new AWS credentials.

#### Issuance of a secret

To issue a secret means to create a Bearer and  (optionally) Session tokens and
put them as an object into container on the NeoFS network. The tokens are
encrypted by a set of gateway keys, so you need to pass them as well.

If a parameter `container-id`  is not set, a new container will be created.

Creation of the bearer token is mandatory, and creation of the session token is
optional. If you want to add the session token you need to add a parameter
`create-session-token`.

Rules for bearer token can be set via param `bearer-rules`, if it is not set,
it will be auto-generated with values:

```
{
    "version": {
        "major": 2,
        "minor": 6
    },
    "containerID": {
        "value": "%CID"
    },
    "records": [
        {
            "operation": "GET",
            "action": "ALLOW",
            "filters": [],
            "targets": [
                {
                    "role": "OTHERS",
                    "keys": []
                }
            ]
        }
    ]
}
```

Rules for session token can be set via param `session-rules`, default value is:
```
{
    "verb": "PUT",
    "wildcard": true,
    "containerID": null
}
```

If `session-rules` is set, but `create-session-token` is not, the session
token will not be created.

Example of a command to issue a secret with custom rules for multiple gates:
```
$ ./neofs-authmate issue-secret --neofs-key user.key \
--peer 192.168.130.71:8080 \
--bearer-rules '{"records":[{"operation":"PUT","action":"ALLOW","filters":[],"targets":[{"role":"OTHERS","keys":[]}]}]}' \
--gate-public-key dd34f6dce9a4ce0990869ec6bd33a40e102a5798881cfe61d03a5659ceee1a64 \
--gate-public-key 20453af9d7f245ff6fdfb1260eaa411ae3be9c519a2a9bf1c98233522cbd0156 \
--create-session-token \
--session-rules '{"verb":"DELETE","wildcard":false,"containerID":{"value":"%CID"}}'

{
  "access_key_id": "5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT_AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM",
  "secret_access_key": "438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c",
  "owner_private_key": "274fdd6e71fc6a6b8fe77bec500254115d66d6d17347d7db0880d2eb80afc72a"
}
```

Access key ID and secret access key are AWS credentials that you can use with
any S3 client.

#### Obtainment of a secret access key

You can get a secret access key associated with access key ID by obtaining a
secret stored on the NeoFS network:

```
 $ ./neofs-authmate obtain-secret --neofs-key user.key \
 --peer 192.168.130.71:8080 \
 --gate-private-key b8ba980eb70b959be99915d2e0ad377809984ccd1dac0a6551907f81c2b33d21 \
 --access-key-id 5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT_AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM

{
  "secret_access_key": "438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c"
}
```

## S3 API supported

Reference:
* [AWS S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/s3-api.pdf)

### Object

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| CopyObject                | Supported               |
| DeleteObject              | Supported               |
| DeleteObjects             | Supported, aka DeleteMultipleObjects |
| GetObject                 | Supported               |
| GetObjectTorrent          | Unsupported, won't be   |
| HeadObject                | Supported               |
| ListObjectParts           | Unsupported             |
| ListObjects               | Supported               |
| ListObjectsV2             | Supported               |
| PutObject                 | Supported (Content-MD5 option is not supported) |
| SelectObjectContent       | Unsupported             |
| WriteGetObjectResponse    | Unsupported             |

#### ACL

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetObjectAcl              | Unsupported             |
| PutObjectAcl              | Unsupported             |

#### Locking

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetObjectLegalHold        | Unsupported             |
| GetObjectLockConfiguration| Unsupported, aka GetBucketObjectLockConfig |
| GetObjectRetention        | Unsupported             |
| PutObjectLegalHold        | Unsupported             |
| PutObjectLockConfiguration| Unsupported, aka PutBucketObjectLockConfig |
| PutObjectRetention        | Unsupported             |

#### Multipart

Should be supported eventually.

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| AbortMultipartUpload      | Unsupported             |
| CompleteMultipartUpload   | Unsupported             |
| CreateMultipartUpload     | Unsupported, aka InitiateMultipartUpload and NewMultipartUpload |
| ListMultipartUploads      | Unsupported             |
| ListParts                 | Unsupported             |
| UploadPart                | Unsupported, aka PutObjectPart  |
| UploadPartCopy            | Unsupported, aka CopyObjectPart |

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

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| ListObjectVersions        | Unsupported, aka ListBucketObjectVersions |
| RestoreObject             | Unsupported             |

### Bucket

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| CreateBucket              | Unsupported, aka PutBucket |
| DeleteBucket              | Unsupported             |
| GetBucketLocation         | Unsupported             |
| HeadBucket                | Supported               |
| ListBuckets               | Supported               |
| PutPublicAccessBlock      | Unsupported             |

#### Acceleration

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| GetBucketAccelerateConfiguration   | Unsupported, aka GetBucketAccelerate |
| PutBucketAccelerateConfiguration   | Unsupported             |

#### ACL

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| GetBucketAcl              | Unsupported             |
| PutBucketAcl              | Unsupported             |

#### Analytics

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| DeleteBucketAnalyticsConfiguration | Unsupported             |
| GetBucketAnalyticsConfiguration    | Unsupported             |
| ListBucketAnalyticsConfigurations  | Unsupported             |
| PutBucketAnalyticsConfiguration    | Unsupported             |


#### Cors

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

| Method                             | Status                  |
| ---------------------------------- | ----------------------- |
| GetBucketNotification              | Unsupported             |
| GetBucketNotificationConfiguration | Unsupported             |
| ListenBucketNotification           | Unsupported, non-standard? |
| PutBucketNotification              | Unsupported             |
| PutBucketNotificationConfiguration | Unsupported             |

#### Ownership controls

| Method                        | Status                  |
| ----------------------------- | ----------------------- |
| DeleteBucketOwnershipControls | Unsupported             |
| GetBucketOwnershipControls    | Unsupported             |
| PutBucketOwnershipControls    | Unsupported             |

#### Policy and replication

| Method                  | Status                  |
| ----------------------- | ----------------------- |
| DeleteBucketPolicy      | Unsupported             |
| DeleteBucketReplication | Unsupported             |
| DeletePublicAccessBlock | Unsupported             |
| GetBucketPolicy         | Unsupported             |
| GetBucketPolicyStatus   | Unsupported             |
| GetBucketReplication    | Unsupported             |
| PostPolicyBucket        | Unsupported, non-standard? |
| PutBucketPolicy         | Unsupported             |
| PutBucketReplication    | Unsupported             |

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
