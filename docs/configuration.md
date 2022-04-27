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
   1. [Notifications](#notifications)


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

Gateway listens on `0.0.0.0:8080` by default, and you can change that with the `--listen_address` option.

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
`--max_clients_count` parameter, the default value is 100. 
`--max_clients_deadline` defines deadline after which the gate sends error `RequestTimeout` to a client, default value 
is 30 seconds.

```shell
$ neofs-s3-gw --max_clients_count 150 --max_clients_deadline 1m
```

### Connection to NeoFS

Timeout to connect to NeoFS nodes can be set with `--connect_timeout` (default 30s)
and timeout to check node health during rebalance`--healthcheck_timeout` (default 15s).

Also, interval to check node health can be specified by `--rebalance_interval` value, default value is 15s.

```shell
$ neofs-s3-gw --healthcheck_timeout 15s --connect_timeout 1m --rebalance_interval 1h
```

### Monitoring and metrics

Pprof and Prometheus are integrated into the gateway, but not enabled by
default. To enable them, use `--pprof` and `--metrics` flags or
`S3_GW_PPROF`/`S3_GW_METRICS` environment variables.

## YAML file and environment variables

Example of a YAML configuration file: [.yaml-example](/config/config.yaml)
Examples of environment variables: [.env-example](/config/config.env).

A path to a configuration file can be specified with `--config` parameter:

```shell
$ neofs-s3-gw --config your-config.yaml
```

Parameters of the following groups can be configured via a `.yaml` file or environment variables only:
1. logging -- logging level
2. caching -- lifetime and size for each cache
3. notifications
4. CORS
5. default policy of placing containers in NeoFS

### Notifications

You can turn on notifications about successful completions of basic operations, and the gateway will send notifications 
via NATS JetStream.

To enable notifications you need:
1. to configure the NATS server with JetStream
2. to specify NATS parameters for the S3 GW. It's ***necessary*** to define a values of `nats.enable` or 
`S3_GW_NATS_ENABLED` as `True` 
3. to configure notifications in a bucket

