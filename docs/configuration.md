# Configuration

There are three ways to configure the S3 GW:

1. CLI parameters
2. YAML file
3. Environment variables

Everything available as a CLI parameter can also be specified via environment variables and almost everything can be
specified via `.yaml` configuration file.

But **not vice versa**, some parameters can be configured only with environment variables/configuration file.
Most of these parameters have default values, therefore, these ways to configure the gateway are optional and
basic configuration can be completed with CLI parameters only.

1. [CLI parameters](#cli-parameters)
    1. [Nodes and weights](#nodes-and-weights)
    2. [Wallet](#wallet)
    3. [Binding and TLS](#listening-on-address-and-TLS)
    4. [RPC endpoint and resolving of bucket names](#rpc-endpoint-and-resolving-of-bucket-names)
    5. [Processing of requests](#processing-of-requests)
    6. [Connection to NeoFS](#connection-to-NeoFS)
    7. [Monitoring and metrics](#monitoring-and-metrics)
2. [YAML file and environment variables](#yaml-file-and-environment-variables)
    1. [Configuration file](#neofs-s3-gateway-configuration-file)

## CLI parameters

### Nodes and weights

You can specify multiple `-p` options to add more NeoFS nodes; this will make
a gateway spread requests equally among them (using weight 1 for every node):

```shell
$ neofs-s3-gw -p 192.168.130.72:8080 -p 192.168.130.71:8080
```

If you want some specific load distribution proportions, use weights and priorities, they
can only be specified via environment variables or a configuration file.

### Wallet

Wallet (`--wallet`) is a mandatory parameter. It is a path to a wallet file. You can provide a passphrase to decrypt
a wallet via env variable or conf file, or you will be asked to enter a password interactively.
You can also specify an account address to use from a wallet using the `--address` parameter.

### Listening on address and TLS

You can make the gateway listen on specific address using the `--listen_address` option.

It can also provide TLS interface for its users, just specify paths to the key and
certificate files via `--tls.key_file` and `--tls.cert_file` parameters. Note
that using these options makes gateway TLS-only. If you need to serve both TLS
and plain text, you either have to run two gateway instances or use some
external redirecting solution.

Example to bind to `192.168.130.130:443` and serve TLS there (keys and nodes are
omitted):

```shell
$ neofs-s3-gw --listen_address 192.168.130.130:443 \
  --tls.key_file=key.pem --tls.cert_file=cert.pem
```

### RPC endpoint and resolving of bucket names

To set RPC endpoint specify a value of parameter `-r` or `--rpc_endpoint`. The parameter is **required if** another
parameter's `--resolve_order` value contains `nns`.

```shell
$ neofs-s3-gw --rpc_endpoint http://morph-chain.neofs.devenv:30333/ --resolve_order nns,dns
```

### Processing of requests

Maximum number of clients whose requests can be handled by the gateway can be specified by the value of
`--max_clients_count` parameter.
`--max_clients_deadline` defines deadline after which the gate sends error `RequestTimeout` to a client.

```shell
$ neofs-s3-gw --max_clients_count 150 --max_clients_deadline 1m
```

### Connection to NeoFS

Timeout to connect to NeoFS nodes can be set with `--connect_timeout`
and timeout to check node health during rebalance`--healthcheck_timeout`.

Also, interval to check node health can be specified by `--rebalance_interval` value.

```shell
$ neofs-s3-gw --healthcheck_timeout 15s --connect_timeout 1m --rebalance_interval 1h
```

### Monitoring and metrics

Pprof and Prometheus are integrated into the gateway. To enable them, use `--pprof` and `--metrics` flags or
`S3_GW_PPROF`/`S3_GW_METRICS` environment variables.

## YAML file and environment variables

Example of a YAML configuration file: [yaml-example](/config/config.yaml)
Examples of environment variables: [env-example](/config/config.env).

A path to a configuration file can be specified with `--config` parameter:

```shell
$ neofs-s3-gw --config your-config.yaml
```

### NeoFS S3 Gateway configuration file

This section contains detailed NeoFS S3 Gateway configuration file description
including default config values and some tips to set up configurable values.

There are some custom types used for brevity:

* `duration` -- string consisting of a number and a suffix. Suffix examples include `s` (seconds), `m` (minutes), `ms` (
  milliseconds).

### Structure

| Section    | Description                             |
|------------|-----------------------------------------|
| no section | [General parameters](#general-section)  |
| `wallet`   | [Wallet configuration](#wallet-section) |
| `peers`    | [Nodes configuration](#peers-section)   |
| `tls`      | [TLS configuration](#tls-section)       |
| `logger`   | [Logger configuration](#logger-section) |
| `cache`    | [Cache configuration](#cache-section)   |
| `nats`     | [NATS configuration](#nats-section)     |
| `cors`     | [CORS configuration](#cors-section)     |

### General section

```yaml
address: NfgHwwTi3wHAS8aFAN243C5vGbkYDpqLHP

listen_address: 0.0.0.0:8084

rpc_endpoint: http://node4.neofs:40332
resolve_order:
  - nns
  - dns

metrics: false
pprof: false

connect_timeout: 30s
healthcheck_timeout: 15s
rebalance_interval: 15s

max_clients_count: 100
max_clients_deadline: 30s

default_policy: REP 3
```

| Parameter              | Type       | Default value  | Description                                                                                                                                                                                                       |
|------------------------|------------|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `address`              | `string`   |                | Account address to get from wallet. If omitted default one will be used.                                                                                                                                          |
| `listen_address`       | `string`   | `0.0.0.0:8080` | The address that the gateway is listening on.                                                                                                                                                                     |
| `rpc_endpoint`         | `string`   |                | The address of the RPC host to which the gateway connects to resolve bucket names.                                                                                                                                |
| `resolve_order`        | `[]string` | `[dns]`        | Order of bucket name resolvers to use.                                                                                                                                                                            |
| `metrics`              | `bool`     | `false`        | Flag to enable and expose the prometheus metrics.                                                                                                                                                                 |
| `pprof`                | `bool`     | `false`        | Flag to enable the profiler.                                                                                                                                                                                      |
| `connect_timeout`      | `duration` | `30s`          | Timeout to connect to a node.                                                                                                                                                                                     |
| `healthcheck_timeout`  | `duration` | `15s`          | Timeout to check node health during rebalance.                                                                                                                                                                    |
| `rebalance_interval`   | `duration` | `15s`          | Interval to check node health.                                                                                                                                                                                    |
| `max_clients_count`    | `int`      | `100`          | Limits for processing of clients' requests.                                                                                                                                                                       |
| `max_clients_deadline` | `duration` | `30s`          | Deadline after which the gate sends error `RequestTimeout` to a client.                                                                                                                                           |
| `default_policy`       | `string`   | `REP 3`        | Default policy of placing containers in NeoFS. If a user sends a request `CreateBucket` and doesn't define policy for placing of a container in NeoFS, the S3 Gateway will put the container with default policy. |

### `wallet` section

```yaml
wallet:
  passphrase: "password"
```

| Parameter    | Type     | Default value | Description                   |
|--------------|----------|---------------|-------------------------------|
| `passphrase` | `string` |               | Passphrase to decrypt wallet. |

### `peers` section

```yaml
# Nodes configuration
# This configuration makes the gateway use the first node (node1.neofs:8080)
# while it's healthy. Otherwise, gateway uses the second node (node2.neofs:8080)
# for 10% of requests and the third node (node3.neofs:8080) for 90% of requests.
# Until nodes with the same priority level are healthy
# nodes with other priority are not used.
# The lower the value, the higher the priority.
peers:
  0:
    address: node1.neofs:8080
    priority: 1
    weight: 1
  1:
    address: node2.neofs:8080
    priority: 2
    weight: 0.1
  2:
    address: node3.neofs:8080
    priority: 2
    weight: 0.9
```

| Parameter  | Type     | Default value | Description                                                                                                                                             |
|------------|----------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `address`  | `string` |               | Address of storage node.                                                                                                                                |
| `priority` | `int`    | `1`           | It allows to group nodes and don't switch group until all nodes with the same priority will be unhealthy. The lower the value, the higher the priority. |
| `weight`   | `float`  | `1`           | Weight of node in the group with the same priority. Distribute requests to nodes proportionally to these values.                                        |

### `tls` section

```yaml
tls:
  cert_file: /path/to/cert
  key_file: /path/to/key
```

| Parameter   | Type     | Default value | Description                  |
|-------------|----------|---------------|------------------------------|
| `cert_file` | `string` |               | Path to the TLS certificate. |
| `key_file`  | `string` |               | Path to the key.             |

### `logger` section

```yaml
logger:
  level: debug
```

| Parameter | Type     | Default value | Description                                                                                        |
|-----------|----------|---------------|----------------------------------------------------------------------------------------------------|
| `level`   | `string` | `debug`       | Logging level.<br/>Possible values:  `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal`. |

### `cache` section

```yaml
cache:
  objects:
    lifetime: 300s
    size: 150
  list:
    lifetime: 1m
    size: 100
  names:
    lifetime: 1m
    size: 1000
  buckets:
    lifetime: 1m
    size: 500
  system:
    lifetime: 2m
    size: 1000
  accessbox:
    lifetime: 5m
    size: 10
```

| Parameter   | Type                              | Default value                     | Description                                                                            |
|-------------|-----------------------------------|-----------------------------------|----------------------------------------------------------------------------------------|
| `objects`   | [Cache config](#cache-subsection) | `lifetime: 5m`<br>`size: 1000000` | Cache for objects (NeoFS headers).                                                     |
| `list`      | [Cache config](#cache-subsection) | `lifetime: 60s`<br>`size: 100000` | Cache which keeps lists of objects in buckets.                                         |
| `names`     | [Cache config](#cache-subsection) | `lifetime: 60s`<br>`size: 10000`  | Cache which contains mapping of nice name to object addresses.                         |
| `buckets`   | [Cache config](#cache-subsection) | `lifetime: 60s`<br>`size: 1000`   | Cache which contains mapping of bucket name to bucket info.                            |
| `system`    | [Cache config](#cache-subsection) | `lifetime: 5m`<br>`size: 10000`   | Cache for system objects in a bucket: bucket settings, notification configuration etc. |
| `accessbox` | [Cache config](#cache-subsection) | `lifetime: 10m`<br>`size: 100`    | Cache which stores access box with tokens by its address.                              |

#### `cache` subsection

```yaml
lifetime: 2m
size: 1000
```

| Parameter  | Type       | Default value    | Description                   |
|------------|------------|------------------|-------------------------------|
| `lifetime` | `duration` | depends on cache | Lifetime of entries in cache. |
| `size`     | `int`      | depends on cache | LRU cache size.               |

### `nats` section

This is an advanced section, use with caution.
You can turn on notifications about successful completions of basic operations, and the gateway will send notifications
via NATS JetStream.

1. to configure the NATS server with JetStream
2. to specify NATS parameters for the S3 GW. It's ***necessary*** to define a values of `nats.enable` or
   `S3_GW_NATS_ENABLED` as `True`
3. to configure notifications in a bucket

```yaml
nats:
  enabled: true
  endpoint: nats://localhost:4222
  timeout: 30s
  cert_file: /path/to/cert
  key_file: /path/to/key
  root_ca: /path/to/ca
```

| Parameter     | Type       | Default value | Description                                          |
|---------------|------------|---------------|------------------------------------------------------|
| `enabled`     | `bool`     | `false`       | Flag to enable the service.                          |
| `endpoint`    | `string`   |               | NATS endpoint to connect to.                         |
| `timeout`     | `duration` | `30s`         | Timeout for the object notification operation.       |
| `certificate` | `string`   |               | Path to the client certificate.                      |
| `key`         | `string`   |               | Path to the client key.                              |
| `ca`          | `string`   |               | Override root CA used to verify server certificates. |

### `cors` section

```yaml
cors:
  default_max_age: 600
```

| Parameter         | Type  | Default value | Description                                          |
|-------------------|-------|---------------|------------------------------------------------------|
| `default_max_age` | `int` | `600`         | Value of `Access-Control-Max-Age` header in seconds. |

