# NeoFS S3 Gateway

NeoFS S3 gateway provides API compatible with Amazon S3 cloud storage service.

## Installation

```go get -u github.com/nspcc-dev/neofs-s3-gw```

Or you can call `make` to build it from the cloned repository (the binary will
end up in `bin/neofs-s3-gw` with authmate helper in `bin/neofs-s3-authmate`).
To build binaries in clean docker environment, call `make docker/all`.

Other notable make targets:

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
   Passed via `--wallet` parameter or `S3_GW_WALLET_PATH` environment variable.

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

## Domains

By default, s3-gw enable only `path-style access`. 
To be able to use both: `virtual-hosted-style` and `path-style` access you must configure `listen_domains`:

```shell
$ neofs-s3-gw -p 192.168.130.72:8080 --wallet wallet.json --listen_domains your.first.domain --listen_domains your.second.domain
```

So now you can use (e.g. `HeadBucket`. Make sure DNS is properly configured):

```shell
$ curl --head http://bucket-name.your.first.domain:8080
HTTP/1.1 200 OK
...
```

or

```shell
$ curl --head http://your.second.domain:8080/bucket-name
HTTP/1.1 200 OK
...
```

Also, you can configure domains using `.env` variables or `yaml` file.

## Documentation

- [Configuration](./docs/configuration.md)
- [NeoFS S3 AuthMate](./docs/authmate.md)
- [NeoFS Tree service](./docs/tree_service.md)
- [AWS CLI basic usage](./docs/aws_cli.md)
- [AWS S3 API compatibility](./docs/aws_s3_compat.md)
- [AWS S3 Compatibility test results](./docs/s3_test_results.md)

## Credits 

Please see [CREDITS](CREDITS.md) for details.
-----------
-----------
