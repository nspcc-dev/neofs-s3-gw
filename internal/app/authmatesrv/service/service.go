package service

import (
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/authmate"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/limits"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs/contracts"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	session2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

type (
	// Config groups the service settings.
	Config struct {
		// Gates are the S3 gateway public keys to issue credentials for when the
		// client names none. A client may ask for any other key just as well.
		Gates keys.PublicKeys

		// MaxLifetime caps the requested credentials lifetime. It also applies when
		// the client asks for no particular expiration.
		MaxLifetime time.Duration

		// Logger to report failures to. Must not be nil.
		Logger *zap.Logger
	}

	// Service issues S3 credentials.
	Service struct {
		cfg Config
	}
)

// New creates a [Service] from the given config.
func New(cfg Config) (*Service, error) {
	switch {
	case len(cfg.Gates) == 0:
		return nil, errors.New("at least one default gate key is required")
	case cfg.MaxLifetime <= 0:
		return nil, errors.New("max lifetime must be positive")
	case cfg.Logger == nil:
		return nil, errors.New("logger is required")
	}

	return &Service{cfg: cfg}, nil
}

// RegisterRoutes attaches the service handlers to the given Echo instance.
func (s *Service) RegisterRoutes(e *echo.Echo) {
	e.GET(PathS3Gates, s.S3Gates)
	e.POST(PathS3Credentials, s.PrepareS3Credentials)
	e.POST(PathCompleteS3Credentials, s.CompleteS3Credentials)
}

// S3Gates returns the S3 gateway keys credentials may be issued for.
func (s *Service) S3Gates(ctx echo.Context) error {
	var resp = S3GatesResponse{Gates: make([]string, 0, len(s.cfg.Gates))}
	for _, gate := range s.cfg.Gates {
		resp.Gates = append(resp.Gates, gate.StringCompressed())
	}

	return ctx.JSON(http.StatusOK, resp)
}

// PrepareS3Credentials forms unsigned session tokens.
func (s *Service) PrepareS3Credentials(ctx echo.Context) error {
	var req S3CredentialsRequest
	if err := ctx.Bind(&req); err != nil {
		return s.badRequest(ctx, "bind", err)
	}

	var issuer user.ID
	if err := issuer.DecodeString(req.Issuer); err != nil {
		return s.badRequest(ctx, "invalid issuer", err)
	}

	gates, err := s.resolveGates(req.Gates)
	if err != nil {
		return s.badRequest(ctx, "invalid gates", err)
	}

	contexts, err := prepareContexts(req.Contexts)
	if err != nil {
		return s.badRequest(ctx, "invalid contexts", err)
	}

	// https://github.com/nspcc-dev/neofs-node/pull/3671#discussion_r2709969518
	issuedAt := time.Now().Add(-30 * time.Second)

	expireAt, err := s.resolveExpiration(req)
	if err != nil {
		return s.badRequest(ctx, "invalid expiration", err)
	}

	ephemeralKey, err := keys.NewPrivateKey()
	if err != nil {
		return s.internalError(ctx, "ephemeral key", err)
	}

	tokens, err := authmate.BuildUnsignedTokens(
		authmate.TokenParams{
			Issuer:          issuer,
			GatesPublicKeys: gates,
			Contexts:        contexts,
			IssuedAt:        issuedAt,
			ExpireAt:        expireAt,
			Secret:          ephemeralKey.Bytes(),
		})
	if err != nil {
		return s.badRequest(ctx, "build session tokens", err)
	}

	var (
		state = issuanceState{EphemeralKey: ephemeralKey.Bytes()}

		resp = S3CredentialsResponse{
			Tokens:    make([]string, 0, len(tokens)),
			ExpiresAt: expireAt.UTC().Format(time.RFC3339),
		}
	)

	for i := range tokens {
		resp.Tokens = append(resp.Tokens, base64.StdEncoding.EncodeToString(tokens[i].SignedData()))
	}

	if resp.State, err = state.encode(); err != nil {
		return s.internalError(ctx, "encode state", err)
	}

	return ctx.JSON(http.StatusOK, resp)
}

// CompleteS3Credentials verifies the token signatures and returns the assembled
// access box together with the S3 secret access key.
func (s *Service) CompleteS3Credentials(ctx echo.Context) error {
	var req CompleteS3CredentialsRequest
	if err := ctx.Bind(&req); err != nil {
		return s.badRequest(ctx, "bind", err)
	}

	state, err := decodeState(req.State)
	if err != nil {
		return s.badRequest(ctx, "invalid state", err)
	}

	ephemeralKey, err := keys.NewPrivateKeyFromBytes(state.EphemeralKey)
	if err != nil {
		return s.badRequest(ctx, "invalid state", fmt.Errorf("ephemeral key: %w", err))
	}

	if len(req.Tokens) == 0 {
		return s.badRequest(ctx, "invalid tokens", errors.New("no tokens to complete"))
	}

	var (
		issuer    user.ID
		tokens    = make([]session2.Token, len(req.Tokens))
		gatesData = make([]*accessbox.GateData, 0, len(req.Tokens))
	)

	for i, signed := range req.Tokens {
		if tokens[i], err = s.completeToken(signed); err != nil {
			return s.badRequest(ctx, fmt.Sprintf("invalid token %d", i), err)
		}

		if i == 0 {
			issuer = tokens[i].Issuer()
		} else if tokens[i].Issuer() != issuer {
			return s.badRequest(ctx, "invalid tokens", errors.New("all tokens must have the same issuer"))
		}

		gatesData = append(gatesData, &accessbox.GateData{SessionTokenV2: &tokens[i]})
	}

	box, secrets, err := accessbox.PackTokens(gatesData, ephemeralKey, ephemeralKey.Bytes())
	if err != nil {
		return s.internalError(ctx, "pack tokens", err)
	}

	if len(req.ContainerPolicies) > 0 {
		if box.ContainerPolicy, err = authmate.ParseContainerPolicies(req.ContainerPolicies); err != nil {
			return s.badRequest(ctx, "invalid container policies", err)
		}
	}

	payload, err := box.Marshal()
	if err != nil {
		return s.internalError(ctx, "marshal access box", err)
	}

	if len(payload) > limits.MaxAccessBoxSize {
		return s.badRequest(ctx, "access box", fmt.Errorf("too big: %d > %d bytes, reduce gates or contexts", len(payload), limits.MaxAccessBoxSize))
	}

	return ctx.JSON(http.StatusOK, CompleteS3CredentialsResponse{
		SecretAccessKey: secrets.AccessKey,
		AccessBox:       base64.StdEncoding.EncodeToString(payload),
		ExpiresAt:       tokens[0].Exp().UTC().Format(time.RFC3339),
	})
}

// resolveGates parses the requested gate keys, any key is allowed. The configured
// ones are used when the client names none.
func (s *Service) resolveGates(gateKeys []string) (keys.PublicKeys, error) {
	if len(gateKeys) == 0 {
		return s.cfg.Gates, nil
	}

	result := make(keys.PublicKeys, 0, len(gateKeys))

	for _, s3Gate := range gateKeys {
		gateKey, err := keys.NewPublicKeyFromString(s3Gate)
		if err != nil {
			return nil, fmt.Errorf("invalid gate key %q: %w", s3Gate, err)
		}

		if !result.Contains(gateKey) {
			result = append(result, gateKey)
		}
	}

	return result, nil
}

// resolveExpiration follows the next order: expiration-rfc3339, then
// expiration-timestamp, then expiration-duration, each overriding the previous
// one. The maximum lifetime applies when none is set.
func (s *Service) resolveExpiration(req S3CredentialsRequest) (time.Time, error) {
	now := time.Now()
	expireAt := now.Add(s.cfg.MaxLifetime)

	if req.ExpirationRfc3339 != nil && *req.ExpirationRfc3339 != "" {
		parsed, err := time.Parse(time.RFC3339, *req.ExpirationRfc3339)
		if err != nil {
			return time.Time{}, fmt.Errorf("expiration-rfc3339 format must be in RFC3339: %w", err)
		}

		expireAt = parsed
	}

	if req.ExpirationTimestamp != nil && *req.ExpirationTimestamp > 0 {
		expireAt = time.Unix(int64(*req.ExpirationTimestamp), 0)
	}

	if req.ExpirationDuration != nil && *req.ExpirationDuration != "" {
		duration, err := time.ParseDuration(*req.ExpirationDuration)
		if err != nil {
			return time.Time{}, fmt.Errorf("expiration-duration format must be a Go duration: %w", err)
		}

		expireAt = now.Add(duration)
	}

	if !expireAt.After(now) {
		return time.Time{}, errors.New("must be in the future")
	}

	if expireAt.Sub(now) > s.cfg.MaxLifetime {
		return time.Time{}, fmt.Errorf("lifetime exceeds the maximum of %s", s.cfg.MaxLifetime)
	}

	return expireAt, nil
}

func prepareContexts(apiContexts []TokenContext) ([]session2.Context, error) {
	// No contexts at all means a single wildcard context with every supported verb.
	if len(apiContexts) == 0 {
		return authmate.BuildContexts(nil)
	}

	var verbsByCnr = make(map[cid.ID][]session2.Verb, len(apiContexts))

	for _, apiContext := range apiContexts {
		var cnrID cid.ID
		if apiContext.ContainerID != "" {
			if err := cnrID.DecodeString(apiContext.ContainerID); err != nil {
				return nil, fmt.Errorf("invalid container id: %w", err)
			}
		}

		if _, ok := verbsByCnr[cnrID]; ok {
			return nil, fmt.Errorf("two different contexts have the same container: %s", cnrID)
		}

		if len(apiContext.Verbs) == 0 {
			return nil, errors.New("context must have at least one verb")
		}

		var verbs = make([]session2.Verb, 0, len(apiContext.Verbs))
		for _, apiVerb := range apiContext.Verbs {
			verb, err := authmate.ParseVerb(string(apiVerb))
			if err != nil {
				return nil, err
			}

			verbs = append(verbs, verb)
		}

		verbsByCnr[cnrID] = verbs
	}

	return authmate.NewContexts(verbsByCnr)
}

func (s *Service) completeToken(signed S3SignedToken) (session2.Token, error) {
	var token session2.Token

	body, err := base64.StdEncoding.DecodeString(signed.Token)
	if err != nil {
		return token, fmt.Errorf("malformed base64 encoding: %w", err)
	}

	if err = token.UnmarshalSignedData(body); err != nil {
		return token, fmt.Errorf("malformed session token: %w", err)
	}

	signatureValue, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return token, fmt.Errorf("couldn't decode signature: %w", err)
	}

	signatureKey, err := base64.StdEncoding.DecodeString(signed.Key)
	if err != nil {
		return token, fmt.Errorf("couldn't decode signature key: %w", err)
	}

	scheme, err := signed.Scheme.scheme()
	if err != nil {
		return token, err
	}

	if scheme == neofscrypto.N3 {
		// Script based signatures can only be checked against the chain.
		token.AttachSignature(neofscrypto.NewN3Signature(signatureValue, signatureKey))
	} else {
		pub, err := keys.NewPublicKeyFromBytes(signatureKey, elliptic.P256())
		if err != nil {
			return token, fmt.Errorf("couldn't parse signature key: %w", err)
		}

		token.AttachSignature(neofscrypto.NewSignatureFromRawKey(scheme, signatureKey, signatureValue))
		if !token.VerifySignature() {
			return token, errors.New("invalid signature")
		}

		if signer := user.NewFromScriptHash(pub.GetScriptHash()); signer != token.Issuer() {
			return token, fmt.Errorf("signed by %s, not by the issuer %s", signer, token.Issuer())
		}
	}

	// Named subjects are never issued here, so nothing has to be resolved.
	if err = token.Validate(&contracts.NoOpNNSResolver{}); err != nil {
		return token, fmt.Errorf("session token validation: %w", err)
	}

	return token, nil
}

func (s *Service) badRequest(ctx echo.Context, msg string, err error) error {
	s.cfg.Logger.Debug(msg, zap.Error(err))
	return ctx.JSON(http.StatusBadRequest, ErrorResponse{Message: msg + ": " + err.Error()})
}

func (s *Service) internalError(ctx echo.Context, msg string, err error) error {
	s.cfg.Logger.Error(msg, zap.Error(err))
	return ctx.JSON(http.StatusInternalServerError, ErrorResponse{Message: msg})
}
