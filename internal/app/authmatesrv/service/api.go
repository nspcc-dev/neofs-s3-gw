package service

import (
	"fmt"

	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
)

const (
	PathS3Credentials         = "/v1/auth/s3"
	PathCompleteS3Credentials = "/v1/auth/s3/complete"
	PathS3Gates               = "/v1/auth/s3/gates"
)

const (
	SchemeDeterministicSHA256 SchemaType = "DETERMINISTIC_SHA256"
	SchemeSHA512              SchemaType = "SHA512"
	SchemeWalletConnect       SchemaType = "WALLETCONNECT"
	SchemeN3                  SchemaType = "N3"
)

const (
	VerbContainerPut             TokenVerb = "CONTAINER_PUT"
	VerbContainerDelete          TokenVerb = "CONTAINER_DELETE"
	VerbContainerSetEACL         TokenVerb = "CONTAINER_SET_EACL"
	VerbContainerSetAttribute    TokenVerb = "CONTAINER_SET_ATTRIBUTE"
	VerbContainerRemoveAttribute TokenVerb = "CONTAINER_REMOVE_ATTRIBUTE"
	VerbObjectPut                TokenVerb = "OBJECT_PUT"
	VerbObjectGet                TokenVerb = "OBJECT_GET"
	VerbObjectHead               TokenVerb = "OBJECT_HEAD"
	VerbObjectSearch             TokenVerb = "OBJECT_SEARCH"
	VerbObjectDelete             TokenVerb = "OBJECT_DELETE"
	VerbObjectRange              TokenVerb = "OBJECT_RANGE"
)

type (
	// SchemaType is a signature scheme type for a session token.
	SchemaType string

	// TokenVerb is a verb that describes the operations allowed by a token.
	TokenVerb string

	// TokenContext narrows a session token to a container and a set of verbs.
	TokenContext struct {
		// ContainerID, if set, narrows the context to this container. An empty one
		// is the wildcard, matching every container.
		ContainerID string `json:"containerID,omitempty"`

		// Verbs allowed in this context. At least one is required.
		Verbs []TokenVerb `json:"verbs,omitempty"`
	}

	// ErrorResponse is returned for every failed request.
	ErrorResponse struct {
		Code    uint32 `json:"code,omitempty"`
		Message string `json:"message"`
	}

	// S3GatesResponse lists the S3 gateway keys the service issues for by default.
	S3GatesResponse struct {
		// Gates are hex encoded compressed public keys.
		Gates []string `json:"gates"`
	}

	// S3CredentialsRequest holds the parameters of the credentials to be issued.
	S3CredentialsRequest struct {
		// Issuer is the token issuer ID (account address), the future owner of the
		// credentials. It must be the one signing the tokens.
		Issuer string `json:"issuer"`

		// Gates are hex encoded compressed public keys of the S3 gateways to issue
		// credentials for, any key goes. The configured ones when omitted.
		Gates []string `json:"gates,omitempty"`

		// Contexts are the session token contexts. If omitted, a single wildcard
		// context with all verbs is used.
		Contexts []TokenContext `json:"contexts,omitempty"`

		// ExpirationRfc3339 specifies the expiration time in RFC3339 format.
		ExpirationRfc3339 *string `json:"expiration-rfc3339,omitempty"`

		// ExpirationTimestamp specifies the exact timestamp of credentials
		// expiration. If set, should be positive.
		ExpirationTimestamp *int `json:"expiration-timestamp,omitempty"`

		// ExpirationDuration specifies the duration until credentials expiration in
		// Go's duration format. Examples:
		//   - "300s" represents 5 minutes.
		//   - "2h45m" represents 2 hours and 45 minutes.
		ExpirationDuration *string `json:"expiration-duration,omitempty"`
	}

	// S3CredentialsResponse carries the tokens to be signed by the client.
	S3CredentialsResponse struct {
		// Tokens are base64 encoded unsigned session v2 token bodies, each must be
		// signed by the issuer and passed back to the complete call.
		Tokens []string `json:"tokens"`

		// State to pass unchanged to the complete call.
		State string `json:"state"`

		// ExpiresAt is the credentials expiration time in RFC3339 format.
		ExpiresAt string `json:"expiresAt"`
	}

	// S3SignedToken is an unsigned session v2 token from the prepare call with its detached signature.
	S3SignedToken struct {
		// Token is the base64 encoded unsigned session v2 token from the prepare call.
		Token string `json:"token"`

		// Key is the Base64 encoded public part of the key that signed the session token.
		// If scheme is N3, the Base64 encoded verifScript.
		Key string `json:"key"`

		// Signature is the Base64 encoded signature for the session v2 token.
		// If scheme is N3, the Base64 encoded invocScript.
		Signature string `json:"signature"`

		// Scheme is the signature scheme.
		Scheme SchemaType `json:"scheme"`
	}

	// CompleteS3CredentialsRequest carries the signatures for the prepared tokens.
	CompleteS3CredentialsRequest struct {
		// State is the state from the prepare call.
		State string `json:"state"`

		// Tokens are the signed session v2 tokens, in the order the prepare call returned them.
		Tokens []S3SignedToken `json:"tokens"`

		// ContainerPolicies maps an S3 LocationConstraint to a NeoFS placement policy.
		ContainerPolicies map[string]string `json:"containerPolicies,omitempty"`
	}

	// CompleteS3CredentialsResponse holds the issued S3 credentials.
	CompleteS3CredentialsResponse struct {
		// SecretAccessKey is the hex encoded secret access key for S3 requests.
		SecretAccessKey string `json:"secretAccessKey"`

		// AccessBox is the base64 encoded credential box.
		AccessBox string `json:"accessBox"`

		// ExpiresAt is the credentials expiration time in RFC3339 format.
		ExpiresAt string `json:"expiresAt"`
	}
)

func (s SchemaType) scheme() (neofscrypto.Scheme, error) {
	switch s {
	case "", SchemeDeterministicSHA256:
		return neofscrypto.ECDSA_DETERMINISTIC_SHA256, nil
	case SchemeSHA512:
		return neofscrypto.ECDSA_SHA512, nil
	case SchemeWalletConnect:
		return neofscrypto.ECDSA_WALLETCONNECT, nil
	case SchemeN3:
		return neofscrypto.N3, nil
	default:
		return 0, fmt.Errorf("unknown signature scheme %q", s)
	}
}
