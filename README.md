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
 * a wallet used to fetch key and communicate with NeoFS nodes
   Passed via `--wallet` parameter or `S3_GW_WALLET` environment variable.

These two commands are functionally equivalent, they run the gate with one
backend node, some keys and otherwise default settings:
```
$ neofs-s3-gw -p 192.168.130.72:8080 --wallet wallet.json

$ S3_GW_PEERS_0_ADDRESS=192.168.130.72:8080 \
  S3_GW_WALLET=wallet.json \
  neofs-s3-gw
```
It's also possible to specify uri scheme (grpc or grpcs) when using `-p` or environment variables:
```
$ neofs-s3-gw -p grpc://192.168.130.72:8080 --wallet wallet.json

$ S3_GW_PEERS_0_ADDRESS=grpcs://192.168.130.72:8080 \
  S3_GW_WALLET=wallet.json \
  neofs-s3-gw
```

## Configuration

In general, everything available as CLI parameter can also be specified via
environment variables, so they're not specifically mentioned in most cases
(see `--help` also). If you prefer a config file you can use it in yaml format.

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

Wallet (`--wallet`) is mandatory parameter. It is a path to wallet file. You can provide password to decrypt wallet
via `S3_GW_WALLET_PASSPHRASE` variable or you will be asked to enter the password interactively. 
You also can specify account address to use from wallet using `--address` parameter.

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

### Yaml file
Configuration file is optional and can be used instead of environment variables/other parameters. 
It can be specified with `--config` parameter:
```
$ neofs-s3-gw --config your-config.yaml
```

Configuration file example:
```
listen_address: 0.0.0.0:8084

wallet:
  passphrase: 123456

logger:
  level: debug

peers:
  0:
    address: s01.neofs.devenv:8080
    weight: 1
```

To know nesting level of variable you need to cut off the prefix `S3_GW` from variable and split the rest parts by `_`.
For example variable `S3_GW_PEERS_0_WEIGHT=1` will be transformed to:
```
peers:
  0:
    weight: 1
```

If parameter doesn't support environment variable (e.g. `--listen_address 0.0.0.0:8084`) form it is used as is:
```
listen_address: 0.0.0.0:8084
```

## NeoFS AuthMate

Authmate is a tool to create gateway AWS credentials. AWS users
are authenticated with access key IDs and secrets, while NeoFS users are
authenticated with key pairs. To complicate things further we have S3 gateway
that usually acts on behalf of some user, but user doesn't necessarily want to
give his keys to the gateway.

To solve this we use NeoFS bearer tokens that are signed by the owner (NeoFS
"user") and that can implement any kind of policy for NeoFS requests allowed
using this token. But tokens can't be used directly as AWS credentials, thus
they're stored on NeoFS as regular objects and access key ID is just an
address of this object while secret is generated randomly.

Tokens are not stored on NeoFS in plaintext, they're encrypted with a set of
gateway keys. So in order for gateway to be able to successfully extract bearer
token the object needs to be stored in a container available for the gateway
to read and it needs to be encrypted with this gateway's key (among others
potentially).

### Variables
Authmate support the following variables to decrypt wallets provided by `--wallet` and `--gate-wallet`
parameters respectevely:
* `AUTHMATE_WALLET_PASSPHRASE`
* `AUTHMATE_WALLET_GATE_PASSPHRASE`
  
If the passphrase is not specified, you will be asked to enter the password interactively:
```
Enter password for wallet.json > 
```

#### Generation of wallet

To generate wallets for gateways, run the following command:

```
$ ./neo-go wallet init -a -w wallet.json

Enter the name of the account > AccountTestName
Enter passphrase > 
Confirm passphrase > 

{
 	"version": "3.0",
 	"accounts": [
 		{
 			"address": "NhLQpDnerpviUWDF77j5qyjFgavCmasJ4p",
 			"key": "6PYUFyYpJ1JGyMrYV8NqeUFLKfpEVHsGGjCYtTDkjnKaSgYizRBZxVerte",
 			"label": "AccountTestName",
 			"contract": {
 				"script": "DCECXCsUZPwUyKHs6nAyyCvJ5s/vLwZkkVtWNC0zWzH8a9dBVuezJw==",
 				"parameters": [
 					{
 						"name": "parameter0",
 						"type": "Signature"
 					}
 				],
 				"deployed": false
 			},
 			"lock": false,
 			"isDefault": false
 		}
 	],
 	"scrypt": {
 		"n": 16384,
 		"r": 8,
 		"p": 8
 	},
 	"extra": {
 		"Tokens": null
 	}
 }

wallet successfully created, file location is wallet.json
```

To get public key from wallet run:
```
$ ./bin/neo-go wallet dump-keys -w wallet.json

NhLQpDnerpviUWDF77j5qyjFgavCmasJ4p (simple signature contract):
025c2b1464fc14c8a1ecea7032c82bc9e6cfef2f0664915b56342d335b31fc6bd7
```

#### Issuance of a secret

To issue a secret means to create a Bearer and  (optionally) Session tokens and
put them as an object into container on the NeoFS network. The tokens are
encrypted by a set of gateway keys, so you need to pass them as well.

If a parameter `container-id`  is not set, a new container will be created.

Creation of the bearer token is mandatory, and creation of the session token is
optional. If you want to add the session token you need to add a parameter
`create-session-token`.

Rules for bearer token can be set via param `bearer-rules` (json-string and file path allowed), if it is not set,
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

Rules for session token can be set via param `session-rules` (json-string and file path allowed), default value is:
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
$ ./neofs-authmate issue-secret --wallet wallet.json \
--peer 192.168.130.71:8080 \
--bearer-rules '{"records":[{"operation":"PUT","action":"ALLOW","filters":[],"targets":[{"role":"OTHERS","keys":[]}]}]}' \
--gate-public-key dd34f6dce9a4ce0990869ec6bd33a40e102a5798881cfe61d03a5659ceee1a64 \
--gate-public-key 20453af9d7f245ff6fdfb1260eaa411ae3be9c519a2a9bf1c98233522cbd0156 \
--create-session-token \
--session-rules '{"verb":"DELETE","wildcard":false,"containerID":{"value":"%CID"}}'

Enter password for wallet.json > 
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
secret stored on the NeoFS network. Here example of providing one password (for `wallet.json`) via env variable 
and other (for `gate-wallet.json`) interactively:

```
 $ AUTHMATE_WALLET_PASSPHRASE=some-pwd \
  ./neofs-authmate obtain-secret --wallet wallet.json \
 --peer 192.168.130.71:8080 \
 --gate-wallet gate-wallet.json \
 --access-key-id 5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT_AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM

Enter password for gate-wallet.json >
{
  "secret_access_key": "438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c"
}
```

## AWS CLI usage

### Configuration

#### Credentials

To configure basic settings that the AWS CLI uses to interact with the Gateway, do the following steps:

1. issue a secret with neofs-authmate tool (see [NeoFS Authmate] (#neofs-authmate))
2. execute the command
```
$ aws configure
```
after you enter this command, the AWS CLI will prompt you for four pieces of information, like in this example
(replace with your own values):
```
AWS Access Key ID [None]: 5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT_AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM
AWS Secret Access Key [None]: 438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c
Default region name [None]: ru 
Default output format [none]: json 
```

### Basic usage

> **_NOTE:_** To specify IP and port of the gate, append `--endpoint-url https://%IP:%PORT` to your commands.

#### Bucket

##### Obtainment of a list of buckets 

To view the list of the buckets in the NeoFS node, to which the gateway is connected, enter the command:
```
$ aws s3 ls 
```

##### Creation of a bucket

At this moment, the gateway supports only canned ACL and doesn't support the setting of location constraints.

To create a bucket, run the command:
```
$ aws s3api create-bucket --bucket %BUCKET_NAME --acl %ACL
```
where `%ACL` can be represented by a hex encoded value or by keywords `public-read-write`, `private`, `public-read`. 
If the parameter is not set, the default value is `private`.



##### Deletion of a bucket 

To delete a bucket, execute the following command:
```
$ aws s3api delete-bucket --bucket %BUCKET_NAME
```

#### Object

##### Obtainment of a list of objects

To view the list of the objects in a bucket, run:
```
$ aws s3api list-objects --bucket %BUCKET_NAME 
```

##### Upload of a file

To upload the file into a bucket in the NeoFS network, run the following command:
```
$ aws s3api put-object --bucket %BUCKET_NAME --key %OBJECT_KEY --body  %FILEPATH
```
where %OBJECT_KEY is a filename of an object in NeoFS

#### Download of a file

To download the file from a bucket in the NeoFS Network, execute:
```
$ aws s3api get-object --bucket  %BUCKET_NAME --key %OBJECT_KEY
```

#### Deletion of a file
To delete the file:
```
$ aws s3api delete-object --bucket %BUCKET_NAME --key %FILE_NAME
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
| ListObjectVersions        | Supported (null-versioning), aka ListBucketObjectVersions |
| RestoreObject             | Unsupported             |

### Bucket

| Method                    | Status                  |
| ------------------------- | ----------------------- |
| CreateBucket              | Supported, aka PutBucket |
| DeleteBucket              | Supported               |
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
