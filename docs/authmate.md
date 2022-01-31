# NeoFS AuthMate

Authmate is a tool to create gateway AWS credentials. AWS users
are authenticated with access key IDs and secrets, while NeoFS users are
authenticated with key pairs. To complicate things further we have S3 gateway
that usually acts on behalf of some user, but user doesn't necessarily want to
give their keys to the gateway.

To solve this, we use NeoFS bearer tokens that are signed by the owner (NeoFS
"user") and that can implement any kind of policy for NeoFS requests allowed
using this token. However, tokens can't be used as AWS credentials directly, thus
they're stored on NeoFS as regular objects, and access key ID is just an
address of this object while secret is generated randomly.

Tokens are not stored on NeoFS in plaintext, they're encrypted with a set of
gateway keys. So in order for a gateway to be able to successfully extract bearer
token, the object needs to be stored in a container available for the gateway
to read, and it needs to be encrypted with this gateway's key (among others
potentially).

## Variables
Authmate supports the following variables to decrypt wallets provided by `--wallet` and `--gate-wallet`
parameters respectevely:
* `AUTHMATE_WALLET_PASSPHRASE`
* `AUTHMATE_WALLET_GATE_PASSPHRASE`
  
If the passphrase is not specified, you will be asked to enter the password interactively:
```
Enter password for wallet.json > 
```

## Generation of wallet

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

## Issuance of a secret

To issue a secret means to create a Bearer and (optionally) Session tokens and
put them as an object into a container on the NeoFS network.

By default, the tool creates a container with a name the same as container ID in NeoFS and ACL 
0x3c8c8cce (all operations are forbidden for `OTHERS` and `BEARER` user groups, 
except for `GET`). 

Also, you can put the tokens into an existing container via `--container-id` 
parameter, but this way is **not recommended**.

The tokens are encrypted by a set of gateway keys, so you need to pass them as well.

Creation of the bearer token is mandatory, while creation of the session token is
optional. 

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

With session token, there is 3 options: 
* append `--session-token` parameter with your custom rules in json format (as a string or file path, see an example below)

**NB!** If you want to allow the user to create buckets you **must** put two session tokens with `PUT` and `SETEACL` rules.

* append `--session-token` parameter with the value `none` -- no session token will be created
* skip the parameter and `authmate` will create and put session tokens with default rules:
```
[
  {
    "verb": "PUT",
    "wildcard": true,
    "containerID": null
  },
  {
    "verb": "DELETE",
    "wildcard": true,
    "containerID": null
  },
  {
    "verb": "SETEACL",
    "wildcard": true,
    "containerID": null
  },
]
```

Rules for mapping of `LocationConstraint` ([aws spec](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html#API_CreateBucket_RequestBody)) 
to `PlacementPolicy` ([neofs spec](https://github.com/nspcc-dev/neofs-spec/blob/master/01-arch/02-policy.md)) 
can be set via param `container-policy` (json-string and file path allowed):
```
{
  "rep-3": "REP 3",
  "complex": "REP 1 IN X CBF 1 SELECT 1 FROM * AS X",
  "example-json-policy": "{\"replicas\":[{\"count\":3,\"selector\":\"SelASD0\"}],\"container_backup_factor\":3,\"selectors\":[{\"name\":\"SelASD0\",\"count\":3,\"filter\":\"*\"}],\"filters\":[]}"
}
```

Example of a command to issue a secret with custom rules for multiple gates:
```
$ ./neofs-authmate issue-secret --wallet wallet.json \
--peer 192.168.130.71:8080 \
--bearer-rules '{"records":[{"operation":"PUT","action":"ALLOW","filters":[],"targets":[{"role":"OTHERS","keys":[]}]}]}' \
--gate-public-key 0313b1ac3a8076e155a7e797b24f0b650cccad5941ea59d7cfd51a024a8b2a06bf \
--gate-public-key 0317585fa8274f7afdf1fc5f2a2e7bece549d5175c4e5182e37924f30229aef967 \
--session-token '[{"verb":"DELETE","wildcard":false,"containerID":{"value":"%CID"}}]'
--container-policy '{"rep-3": "REP 3"}'

Enter password for wallet.json > 
{
  "access_key_id": "5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT0AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM",
  "secret_access_key": "438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c",
  "owner_private_key": "274fdd6e71fc6a6b8fe77bec500254115d66d6d17347d7db0880d2eb80afc72a",
  "container_id":"5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT"
}
```

Access key ID and secret access key are AWS credentials that you can use with
any S3 client.

Access key ID consists of Base58 encoded containerID(cid) and objectID(oid) stored on the NeoFS network and containing 
the secret. Format of access_key_id: `%cid0%oid`, where 0(zero) is a delimiter.

## Obtainment of a secret access key

You can get a secret access key associated with an access key ID by obtaining a
secret stored on the NeoFS network. Here is an example of providing one password (for `wallet.json`) via env variable 
and the other (for `gate-wallet.json`) interactively:

```
 $ AUTHMATE_WALLET_PASSPHRASE=some-pwd \
  ./neofs-authmate obtain-secret --wallet wallet.json \
 --peer 192.168.130.71:8080 \
 --gate-wallet gate-wallet.json \
 --access-key-id 5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT0AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM

Enter password for gate-wallet.json >
{
  "secret_access_key": "438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c"
}
```
