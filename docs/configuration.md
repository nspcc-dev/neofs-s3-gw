# Configuration

Actually, everything available as a CLI parameter can also be specified via
environment variables, so they're not specifically mentioned in most cases
(see `--help` also). If you prefer a config file you can use it in yaml format.

## Nodes and weights

You can specify multiple `-p` options to add more NeoFS nodes; this will make
a gateway spread requests equally among them (using weight 1 for every node):

```
$ neofs-s3-gw -p 192.168.130.72:8080 -p 192.168.130.71:8080
```
If you want some specific load distribution proportions, use weights, but keep it in mind that they
can only be specified via environment variables:

```
$ S3_GW_PEERS_0_ADDRESS=192.168.130.72:8080 S3_GW_PEERS_0_WEIGHT=9 \
  S3_GW_PEERS_1_ADDRESS=192.168.130.71:8080 S3_GW_PEERS_1_WEIGHT=1 neofs-s3-gw
```
This command will make gateway use 192.168.130.72 for 90% of the requests and
192.168.130.71 for the remaining 10%.

## Key

Wallet (`--wallet`) is a mandatory parameter. It is a path to a wallet file. You can provide password to decrypt a wallet
via `S3_GW_WALLET_PASSPHRASE` variable or you will be asked to enter a password interactively. 
You can also specify an account address to use from a wallet using `--address` parameter.

## Binding and TLS

Gateway binds to `0.0.0.0:8080` by default, and you can change that with
`--listen_address` option.

It can also provide TLS interface for its users, just specify paths to the key and
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

## Monitoring and metrics

Pprof and Prometheus are integrated into the gateway, but not enabled by
default. To enable them, use `--pprof` and `--metrics` flags or
`S3_GW_PPROF`/`S3_GW_METRICS` environment variables.

## Yaml file
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

To know the nesting level of the variable, you need to cut off the prefix `S3_GW` from the variable and split the rest parts by `_`.
For example, variable `S3_GW_PEERS_0_WEIGHT=1` will be transformed to:
```
peers:
  0:
    weight: 1
```

If a parameter doesn't support environment variable (e.g. `--listen_address 0.0.0.0:8084`) form, it is used as:
```
listen_address: 0.0.0.0:8084
```

### Default policy of placing containers in NeoFS

If a user sends a request `CreateBucket` and doesn't define policy for placing of a container in NeoFS, the S3 Gateway 
will put the container with default policy. It can be specified via environment variable, e.g.: 
```
S3_GW_DEFAULT_POLICY=REP 1 CBF 1 SELECT 1 FROM *
```
or via `.yaml` config file, e.g.:
```
default_policy: REP 1
```

If the value is not set at all it will be set as `REP 3`.

### Cache parameters

Parameters for caches in s3-gw can be specified in a .yaml config file. E.g.:
```
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
If invalid values are set, the gateway will use default values instead.
