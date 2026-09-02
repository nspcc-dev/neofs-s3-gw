# NeoFS S3 Authmate service

`neofs-s3-authmate` issues S3 credentials from the command line, which means it needs the user's private key. The
authmate service does the same job over HTTP without ever seeing that key: it builds the session tokens, the client
signs them, and the service assembles the result into an access box (a "keybox") and hands it back. What to do with that
box afterwards is up to the client.

See [authmate.md](authmate.md) for the credentials model itself.

1. [Flow](#flow)
2. [API](#api)
    1. [GET /v1/auth/s3/gates](#get-v1auths3gates)
    2. [POST /v1/auth/s3](#post-v1auths3)
    3. [POST /v1/auth/s3/complete](#post-v1auths3complete)
    4. [Errors](#errors)
3. [What the client does next](#what-the-client-does-next)
4. [Configuration](#configuration)

## Flow

```
client -> GET /v1/auth/s3/gates (Default key set suggested by the service)

client -> POST /v1/auth/s3 {issuer, gates, contexts, expiration} -> server builds unsigned session tokens,
returns these tokens and state

(sign every token with the issuer key)

client -> POST /v1/auth/s3/complete {state, tokens: [{token, signature}]} -> server verifies the signatures, packs the box.
Server returns access box + secret access key.

(client makes whatever it wants with this box)
```

## API

All requests and responses are JSON. CORS is enabled for every origin.

### GET `/v1/auth/s3/gates`

Lists the S3 gateway keys the service uses when a user sends an empty gates list.

```shell
curl -s http://localhost:8090/v1/auth/s3/gates
```
```json
{
    "gates":[
       "025c2b1464fc14c8a1ecea7032c82bc9e6cfef2f0664915b56342d335b31fc6bd7",
       "0317585fa8274f7afdf1fc5f2a2e7bece549d5175c4e5182e37924f30229aef967"
    ]
}
```

### POST `/v1/auth/s3`

Builds unsigned session tokens carrying a fresh S3 secret encrypted for the requested gateways.

| Field                  | Required | Description                                                                                                                |
|------------------------|----------|----------------------------------------------------------------------------------------------------------------------------|
| `issuer`               | yes      | NeoFS user ID (NbUgTSFvPmsRxmGeWpuuGeJUoRoi6PErcM) of the future credentials owner. It must be the one signing the tokens. |
| `gates`                | no       | Hex encoded public keys of the gateways to issue for, any key is accepted. The configured ones when omitted.               |
| `contexts`             | no       | Session token contexts. A single wildcard context with every verb when omitted.                                            |
| `expiration-rfc3339`   | no       | Expiration time in RFC3339 format, e.g. `"2026-12-31T23:59:59Z"`.                                                          |
| `expiration-timestamp` | no       | Exact expiration timestamp. If set, should be positive.                                                                    |
| `expiration-duration`  | no       | Duration until expiration in Go's duration format, e.g. `"2h45m"`.                                                         |

The expiration fields are evaluated in the order they are listed above and later values override earlier ones. With none
of them set, `limits.max_lifetime` applies, and none of them may exceed it.

Each entry of `contexts` is:

| Field         | Required | Description                                                                      |
|---------------|----------|----------------------------------------------------------------------------------|
| `containerID` | no       | Narrows the context to this container. The wildcard, matching all, when omitted. |
| `verbs`       | yes      | Operations allowed in this context.                                              |

Available verbs:
- `CONTAINER_PUT`
- `CONTAINER_DELETE`
- `CONTAINER_SET_EACL`
- `CONTAINER_SET_ATTRIBUTE`
- `CONTAINER_REMOVE_ATTRIBUTE`
- `OBJECT_PUT`
- `OBJECT_GET`
- `OBJECT_HEAD`
- `OBJECT_SEARCH`
- `OBJECT_DELETE`
- `OBJECT_RANGE`

> Creating buckets needs both `CONTAINER_PUT` and `CONTAINER_SET_EACL`.
> Unlike the `s3-authmate` CLI, this service does not add them by default.

```shell
curl -s -X POST http://localhost:8090/v1/auth/s3 -H 'Content-Type: application/json' -d '{
  "issuer": "NbUgTSFvPmsRxmGeWpuuGeJUoRoi6PErcM",
  "expiration-duration": "24h",
  "contexts": [
    {"verbs": ["OBJECT_GET", "OBJECT_HEAD"]},
    {"containerID": "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1", "verbs": ["OBJECT_PUT"]}
  ]
}'
```
```json
{
   "tokens":["..."],
   "state":"...",
   "expiresAt":"2026-08-27T09:17:52Z"}
```

Each entry of `tokens` is a base64 encoded session token body. The client must sign every one of them and return them
all to the complete call.

`state` is base64 encoded JSON carrying the ephemeral key the tokens were built with, which is also the S3 secret the
complete call returns. The service keeps no copy of it, so the state is a credential: serve the API over TLS and do not
hand the state to anyone who may not have the credentials. There is nothing instance-specific in it, any instance of
the service can complete it.

The state and the tokens must come from the same prepare call. Nothing verifies that: a box completed from a state of
one call and tokens of another is assembled and returned happily, and the gateways then decrypt a secret out of it that
is not the one the client got.

### POST `/v1/auth/s3/complete`

Verifies the signatures and returns the assembled access box.

| Field               | Required | Description                                                         |
|---------------------|----------|---------------------------------------------------------------------|
| `state`             | yes      | The `state` from the prepare call, unchanged.                       |
| `tokens`            | yes      | The signed tokens of that same prepare call.                        |
| `containerPolicies` | no       | `LocationConstraint` to NeoFS placement policy mapping for the box. |

Every element of `tokens` is:

| Field       | Description                                                                                                     |
|-------------|-----------------------------------------------------------------------------------------------------------------|
| `token`     | The base64 encoded token from the prepare call, unchanged.                                                      |
| `key`       | Base64 encoded public key that signed the token. Base64 encoded verification script for the `N3` scheme.        |
| `signature` | Base64 encoded signature. Base64 encoded invocation script for the `N3` scheme.                                 |
| `scheme`    | One of `DETERMINISTIC_SHA256` (default, the native NeoFS one), `SHA512`, `WALLETCONNECT`, `N3`.                 |

```shell
curl -s -X POST http://localhost:8090/v1/auth/s3/complete -H 'Content-Type: application/json' -d @signed.json
```
```json
{
   "secretAccessKey":"770a5f637bd08adba1e7d2a547dab1022a504c526711efd65f4bcc6cbfc93bc2",
   "accessBox":"...",
   "expiresAt":"2026-08-27T09:17:52Z"
}
```

### Errors

Anything the client got wrong is a `400`, including a completed access box that would not fit into the `64 KB` an
S3 gateway is willing to read — ask for fewer gateways or fewer contexts in that case.

## What the client does next

The service stops at handing over the box. To turn it into working AWS credentials the client has to:

1. Store the box as a NeoFS object in a container the gateways can `GET`. The
   `s3-authmate` CLI uses a `<unix nano>_access.box` `FilePath` attribute, a
   `Timestamp` attribute and an `__NEOFS__EXPIRATION_EPOCH` matching the credentials expiration.
   If the target gateway runs with a namespace, set the `namespace` object attribute to it,
   otherwise the gateway rejects the box.
2. Use `<container id>0<object id>` as `aws_access_key_id` and the returned
   `secretAccessKey` as `aws_secret_access_key`. The `0` is a delimiter: base58 has no zero digit.

## Configuration

The service reads a YAML config file given with `--config`.
See [config/authmatesrv.yaml](../config/authmatesrv.yaml) for a complete example, and run `neofs-s3-authmatesrv --help`
for the flags and the resulting variables.

### Structure

| Section  | Description                             |
|----------|-----------------------------------------|
| `server` | [Server configuration](#server-section) |
| `logger` | [Logger configuration](#logger-section) |
| `gates`  | [Default gateway keys](#gates-section)  |
| `limits` | [Issuance limits](#limits-section)      |

The service holds no key of its own: it never signs anything, neither on the network nor in the issuance flow.

### `server` section

```yaml
server:
  address: 0.0.0.0:8090
  tls:
    enabled: false
    cert_file: /path/to/cert
    key_file: /path/to/key
```

| Parameter       | Type     | Default value    | Description                                   |
|-----------------|----------|------------------|-----------------------------------------------|
| `address`       | `string` | `localhost:8090` | Address to listen on.                         |
| `tls.enabled`   | `bool`   | `false`          | Serve HTTPS. Implied when both files are set. |
| `tls.cert_file` | `string` |                  | Path to the TLS certificate.                  |
| `tls.key_file`  | `string` |                  | Path to the TLS key.                          |

Certificates are read at startup only; restart the service to pick up new ones.

### `logger` section

```yaml
logger:
  level: info
  encoding: console
  timestamp: false
```

| Parameter   | Type     | Default value | Description                                                            |
|-------------|----------|---------------|------------------------------------------------------------------------|
| `level`     | `string` | `info`        | One of `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal`.   |
| `encoding`  | `string` | `console`     | `console` or `json`.                                                   |
| `timestamp` | `bool`   | `false`       | Force timestamps on. They are on by default when stdout is a terminal. |

Rejected requests are logged at `debug` level with the reason.

### `gates` section

The S3 gateway public keys credentials are issued for when a request names none, hex encoded compressed `secp256r1`
keys. At least one is required. They are a default, not a restriction: a request naming any other key is served just
the same.

```yaml
gates:
  - 025c2b1464fc14c8a1ecea7032c82bc9e6cfef2f0664915b56342d335b31fc6bd7
  - 0317585fa8274f7afdf1fc5f2a2e7bece549d5175c4e5182e37924f30229aef967
```

As an environment variable the keys are separated by spaces:

```
S3_AUTHMATESRV_GATES="025c2b1464fc... 0317585fa827..."
```

### `limits` section

```yaml
limits:
  max_lifetime: 720h
  max_request_size: 1048576
```

| Parameter          | Type       | Default value | Description                                                                                |
|--------------------|------------|---------------|--------------------------------------------------------------------------------------------|
| `max_lifetime`     | `duration` | `720h`        | Maximum credentials lifetime a client may ask for, and the lifetime when it asks for none. |
| `max_request_size` | `int`      | `1048576`     | Maximum request body size in bytes.                                                        |

Regardless of these, an issuance is rejected on completion when the resulting access box would exceed the 64 KB an S3
gateway reads (see
[#1332](https://github.com/nspcc-dev/neofs-s3-gw/issues/1332)). That is roughly 500 gateways with the default context,
so keep the `gates` list well below that.
