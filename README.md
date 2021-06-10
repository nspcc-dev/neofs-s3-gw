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
 * a key used for client authentication
   Passed via `--auth-key` parameter or `S3_GW_AUTH-KEY` environment variable.
   To generate it use `neofs-authmate generate-keys` command.

These two commands are functionally equivalent, they run the gate with one
backend node, some keys and otherwise default settings:
```
$ neofs-s3-gw -p 192.168.130.72:8080 --neofs-key KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr \
  --auth-key a04edd5b3c497eed83be25fb136bafd056928c17986440745775223615f2cbab

$ S3_GW_PEERS_0_ADDRESS=192.168.130.72:8080 \
  S3_GW_NEOFS-KEY=KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr \
  S3_GW_AUTH-KEY=a04edd5b3c497eed83be25fb136bafd056928c17986440745775223615f2cbab \
  neofs-s3-gw
```
It's also possible to specify uri scheme (grpc or grpcs) when using `-p` or environment variables:
```
$ neofs-s3-gw -p grpc://192.168.130.72:8080 --neofs-key KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr \
  --auth-key a04edd5b3c497eed83be25fb136bafd056928c17986440745775223615f2cbab

$ S3_GW_PEERS_0_ADDRESS=grpcs://192.168.130.72:8080 \
  S3_GW_NEOFS-KEY=KxDgvEKzgSBPPfuVfw67oPQBSjidEiqTHURKSDL1R7yGaGYAeYnr \
  S3_GW_AUTH-KEY=a04edd5b3c497eed83be25fb136bafd056928c17986440745775223615f2cbab \
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

### Keys

NeoFS (`--neofs-key`) and authentication (`--auth-key`) keys are mandatory
parameters. NeoFS key can be a path to private key file (as raw bytes), a hex
string or (unencrypted) WIF string. Authentication key is either a path to
raw private key file or a hex string.

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


## S3 API supported

Reference:
* [AWS S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/s3-api.pdf)

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
| 11  | DeleteMultipleObjects     | Supported               |
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
| 33  | HeadBucket                | Supported               |
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

To generate key pairs for gateways, run the following command (`--count` is 1
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

To issue a secret means to create a Bearer token and put it as an object into
container on the NeoFS network. The token is encrypted by a set of gateway
keys, so you need to pass them as well.

If a parameter `container-id`  is not set, a new container will be created.

If a parameter `rules` is not set, it will be auto-generated with values: 

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

Example of a command to issue a secret with custom rules for multiple gates:
```
$ ./neofs-authmate issue-secret --neofs-key user.key \
--peer 192.168.130.71:8080 \ 
--rules '{"records":[{"operation":"PUT","action":"ALLOW","filters":[],"targets":[{"role":"OTHERS","keys":[]}]}]}' \ 
--gate-public-key dd34f6dce9a4ce0990869ec6bd33a40e102a5798881cfe61d03a5659ceee1a64 \
--gate-public-key 20453af9d7f245ff6fdfb1260eaa411ae3be9c519a2a9bf1c98233522cbd0156

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
