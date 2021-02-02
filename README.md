# NeoFS S3 Gate

## Example of configuration

```
# Flags
      --pprof                           enable pprof
      --metrics                         enable prometheus metrics
  -h, --help                            show help
  -v, --version                         show version
      --neofs-key string                set value to hex string, WIF string, or path to NeoFS private key file
      --auth-key string                 set path to file with auth (curve25519) private key to use in auth scheme
      --verbose                         set debug mode of gRPC connections
      --request_timeout duration        set gRPC request timeout (default 15s)
      --connect_timeout duration        set gRPC connect timeout (default 30s)
      --rebalance_timer duration        set gRPC connection rebalance timer (default 15s)
      --max_clients_count int           set max-clients count (default 100)
      --max_clients_deadline duration   set max-clients deadline (default 30s)
  -t, --con_ttl duration                set gRPC connection time to live (default 5m0s)
      --listen_address string           set address to listen (default "0.0.0.0:8080")
  -p, --peers stringArray               set NeoFS nodes
  -d, --listen_domains stringArray      set domains to be listened

# Environments

S3_GW_AUTH-KEY = 
S3_GW_NEOFS-KEY =
S3_GW_CON_TTL = 5m0s
S3_GW_CONNECT_TIMEOUT = 30s
S3_GW_REBALANCE_TIMER = 15s
S3_GW_REQUEST_TIMEOUT = 15s
S3_GW_KEEPALIVE_PERMIT_WITHOUT_STREAM = true
S3_GW_KEEPALIVE_TIME = 10s
S3_GW_KEEPALIVE_TIMEOUT = 10s
S3_GW_LISTEN_ADDRESS = 0.0.0.0:8080
S3_GW_LISTEN_DOMAINS = []
S3_GW_LOGGER_FORMAT = console
S3_GW_LOGGER_LEVEL = debug
S3_GW_LOGGER_NO_CALLER = false
S3_GW_LOGGER_NO_DISCLAIMER = true
S3_GW_LOGGER_SAMPLING_INITIAL = 1000
S3_GW_LOGGER_SAMPLING_THEREAFTER = 1000
S3_GW_LOGGER_TRACE_LEVEL = panic
S3_GW_MAX_CLIENTS_COUNT = 100
S3_GW_MAX_CLIENTS_DEADLINE = 30s
S3_GW_METRICS = false
S3_GW_PPROF = false
S3_GW_VERBOSE = false

# Peers preset

S3_GW_PEERS_[N]_ADDRESS = string
S3_GW_PEERS_[N]_WEIGHT = 0..1 (float)
```

## Reference Resources

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

