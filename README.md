# NeoFS S3 Gate

## Example of configuration

```
# Flags
      --pprof                           enable pprof
      --metrics                         enable prometheus metrics
  -h, --help                            show help
  -v, --version                         show version
      --neofs-key string                set value to hex string, WIF string, or path to NeoFS private key file (use "generated" to generate key) (default "generated")
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

# Environments

S3_AUTH-KEY = 
S3_CON_TTL = 5m0s
S3_CONNECT_TIMEOUT = 30s
S3_KEEPALIVE_PERMIT_WITHOUT_STREAM = true
S3_KEEPALIVE_TIME = 10s
S3_KEEPALIVE_TIMEOUT = 10s
S3_LISTEN_ADDRESS = 0.0.0.0:8080
S3_LOGGER_FORMAT = console
S3_LOGGER_LEVEL = debug
S3_LOGGER_NO_DISCLAIMER = true
S3_LOGGER_SAMPLING_INITIAL = 1000
S3_LOGGER_SAMPLING_THEREAFTER = 1000
S3_LOGGER_TRACE_LEVEL = panic
S3_MAX_CLIENTS_COUNT = 100
S3_MAX_CLIENTS_DEADLINE = 30s
S3_METRICS = false
S3_NEOFS-KEY = generated
S3_PPROF = false
S3_REBALANCE_TIMER = 15s
S3_REQUEST_TIMEOUT = 15s
S3_VERBOSE = false

# Peers preset

S3_PEERS_[N]_ADDRESS = string
S3_PEERS_[N]_WEIGHT = 0..1 (float)
``` 

---
<footer>

#### MinIO Fork

Forked from https://github.com/minio/minio (https://github.com/minio/minio/releases/tag/RELEASE.2020-07-02T00-15-09Z)

</footer>
