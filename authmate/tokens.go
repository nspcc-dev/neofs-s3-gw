package authmate

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	session2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// SecretLength is the length of an S3 secret access key in bytes.
const SecretLength = 32

// TokenParams groups parameters for building session v2 tokens.
type TokenParams struct {
	// Issuer of the tokens, the future owner of the credentials.
	Issuer user.ID

	// GatesPublicKeys are the S3 gateways public keys.
	GatesPublicKeys []*keys.PublicKey

	// Contexts to be authorized by the tokens, see [BuildContexts].
	Contexts []session2.Context

	// IssuedAt is used for both iat and nbf claims.
	IssuedAt time.Time

	// ExpireAt is the exp claim.
	ExpireAt time.Time

	// Secret is the S3 secret access key, [SecretLength] bytes long. It doubles as
	// the ECDH sender key the secret itself is encrypted with, whose public part is
	// stored in the access box, so it must be a private key produced by
	// [keys.NewPrivateKey].
	Secret []byte
}

// BuildUnsignedTokens builds unsigned session v2 tokens for the given parameters.
func BuildUnsignedTokens(p TokenParams) ([]session2.Token, error) {
	if len(p.GatesPublicKeys) == 0 {
		return nil, errors.New("no gate public keys")
	}

	if len(p.Secret) != SecretLength {
		return nil, fmt.Errorf("invalid secret length: expected %d, got %d", SecretLength, len(p.Secret))
	}

	ephemeralKey, err := keys.NewPrivateKeyFromBytes(p.Secret)
	if err != nil {
		return nil, fmt.Errorf("secret as ephemeral key: %w", err)
	}

	var tokens []session2.Token

	for chunk := range slices.Chunk(p.GatesPublicKeys, session2.MaxSubjectsPerToken) {
		var (
			tokenV2 session2.Token
			targets = make([]session2.Target, 0, len(chunk))
			appData = make([]byte, 0, len(chunk)*accessbox.EncryptedSecretLength)
		)

		for _, gateKey := range chunk {
			targets = append(targets, session2.NewTargetUser(user.NewFromScriptHash(gateKey.GetScriptHash())))

			enc, err := accessbox.Encrypt(ephemeralKey, gateKey, p.Secret)
			if err != nil {
				return nil, fmt.Errorf("encrypt secret: %w", err)
			}

			appData = append(appData, enc...)
		}

		if err := tokenV2.SetSubjects(targets); err != nil {
			return nil, fmt.Errorf("set subjects: %w", err)
		}

		if err := tokenV2.SetContexts(p.Contexts); err != nil {
			return nil, fmt.Errorf("set contexts: %w", err)
		}

		if err := tokenV2.SetAppData(appData); err != nil {
			return nil, fmt.Errorf("set app data: %w", err)
		}

		tokenV2.SetNbf(p.IssuedAt)
		tokenV2.SetIat(p.IssuedAt)
		tokenV2.SetExp(p.ExpireAt)
		tokenV2.SetIssuer(p.Issuer)
		tokenV2.SetVersion(session2.TokenCurrentVersion)

		tokens = append(tokens, tokenV2)
	}

	return tokens, nil
}
