package service

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs/contracts"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	session2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// testContainerID is an arbitrary well-formed container ID.
const testContainerID = "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1"

type testApiService struct {
	echo    *echo.Echo
	service *Service
	gates   []*keys.PrivateKey
	user    *keys.PrivateKey
	issuer  user.ID
}

func newTestApiService(t *testing.T, gatesNum int) *testApiService {
	userKey, err := keys.NewPrivateKey()
	require.NoError(t, err)

	var (
		gates    = make([]*keys.PrivateKey, 0, gatesNum)
		gateKeys = make(keys.PublicKeys, 0, gatesNum)
	)

	for range gatesNum {
		gateKey, err := keys.NewPrivateKey()
		require.NoError(t, err)

		gates = append(gates, gateKey)
		gateKeys = append(gateKeys, gateKey.PublicKey())
	}

	service, err := New(Config{
		Gates:       gateKeys,
		MaxLifetime: 720 * time.Hour,
		Logger:      zap.NewNop(),
	})
	require.NoError(t, err)

	e := echo.New()
	service.RegisterRoutes(e)

	return &testApiService{
		echo:    e,
		service: service,
		gates:   gates,
		user:    userKey,
		issuer:  user.NewAutoIDSignerRFC6979(userKey.PrivateKey).UserID(),
	}
}

func (env *testApiService) requestListGates(t *testing.T) (*httptest.ResponseRecorder, S3GatesResponse) {
	rec := httptest.NewRecorder()
	env.echo.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathS3Gates, nil))

	var resp S3GatesResponse
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}

	return rec, resp
}

func (env *testApiService) requestPrepare(t *testing.T, req S3CredentialsRequest) (*httptest.ResponseRecorder, S3CredentialsResponse) {
	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, PathS3Credentials, bytes.NewReader(body))
	httpReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	env.echo.ServeHTTP(rec, httpReq)

	var resp S3CredentialsResponse
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}

	return rec, resp
}

func (env *testApiService) requestComplete(t *testing.T, req CompleteS3CredentialsRequest) (*httptest.ResponseRecorder, CompleteS3CredentialsResponse) {
	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, PathCompleteS3Credentials, bytes.NewReader(body))
	httpReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	rec := httptest.NewRecorder()
	env.echo.ServeHTTP(rec, httpReq)

	var resp CompleteS3CredentialsResponse
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}

	return rec, resp
}

// signTokens signs the requestPrepare tokens the way a client would.
func signTokens(t *testing.T, tokens []string, key *keys.PrivateKey) []S3SignedToken {
	signer := user.NewAutoIDSignerRFC6979(key.PrivateKey)
	signed := make([]S3SignedToken, 0, len(tokens))

	for _, token := range tokens {
		body, err := base64.StdEncoding.DecodeString(token)
		require.NoError(t, err)

		signature, err := signer.Sign(body)
		require.NoError(t, err)

		signed = append(signed, S3SignedToken{
			Token:     token,
			Key:       base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
			Signature: base64.StdEncoding.EncodeToString(signature),
			Scheme:    SchemeDeterministicSHA256,
		})
	}

	return signed
}

func TestCredentialsFlow(t *testing.T) {
	testService := newTestApiService(t, 3)

	rec, prepared := testService.requestPrepare(t, S3CredentialsRequest{Issuer: testService.issuer.EncodeToString()})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, prepared.Tokens, 1)
	require.NotEmpty(t, prepared.State)

	// The client can inspect what it is about to sign.
	body, err := base64.StdEncoding.DecodeString(prepared.Tokens[0])
	require.NoError(t, err)

	var unsigned session2.Token
	require.NoError(t, unsigned.UnmarshalSignedData(body))
	require.Equal(t, testService.issuer, unsigned.Issuer())
	require.Len(t, unsigned.Subjects(), len(testService.gates))
	require.WithinDuration(t, time.Now().Add(720*time.Hour), unsigned.Exp(), time.Minute)

	rec, completed := testService.requestComplete(t, CompleteS3CredentialsRequest{
		State:  prepared.State,
		Tokens: signTokens(t, prepared.Tokens, testService.user),
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, completed.SecretAccessKey, 64) // 32 bytes, hex encoded.
	require.Equal(t, prepared.ExpiresAt, completed.ExpiresAt)

	// The secret is the ephemeral key the box is packed with.
	state, err := decodeState(prepared.State)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(state.EphemeralKey), completed.SecretAccessKey)

	payload, err := base64.StdEncoding.DecodeString(completed.AccessBox)
	require.NoError(t, err)

	var box accessbox.AccessBox
	require.NoError(t, box.Unmarshal(payload))

	resolver := &contracts.NoOpNNSResolver{}

	// Every gateway must find the very same secret the client was given.
	for _, gateKey := range testService.gates {
		gateData, err := box.GetTokens(gateKey, resolver)
		require.NoError(t, err)
		require.Equal(t, completed.SecretAccessKey, gateData.AccessKey)
		require.Equal(t, testService.issuer, gateData.SessionTokenV2.Issuer())
		require.True(t, gateData.SessionTokenV2.VerifySignature())
		require.NoError(t, gateData.SessionTokenV2.Validate(resolver))
	}

	// A key the credentials were not issued for gets nothing.
	stranger, err := keys.NewPrivateKey()
	require.NoError(t, err)

	_, err = box.GetTokens(stranger, resolver)
	require.Error(t, err)
}

func TestCredentialsFlowManyGates(t *testing.T) {
	const gatesNum = 20

	testService := newTestApiService(t, gatesNum)

	rec, prepared := testService.requestPrepare(t, S3CredentialsRequest{Issuer: testService.issuer.EncodeToString()})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, prepared.Tokens, 3) // 8 + 8 + 4.

	rec, completed := testService.requestComplete(t, CompleteS3CredentialsRequest{
		State:  prepared.State,
		Tokens: signTokens(t, prepared.Tokens, testService.user),
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	payload, err := base64.StdEncoding.DecodeString(completed.AccessBox)
	require.NoError(t, err)

	var box accessbox.AccessBox
	require.NoError(t, box.Unmarshal(payload))

	for _, gateKey := range testService.gates {
		gateData, err := box.GetTokens(gateKey, &contracts.NoOpNNSResolver{})
		require.NoError(t, err)
		require.Equal(t, completed.SecretAccessKey, gateData.AccessKey)
	}
}

func TestGates(t *testing.T) {
	testService := newTestApiService(t, 2)

	rec, resp := testService.requestListGates(t)
	require.Equal(t, http.StatusOK, rec.Code)

	require.Len(t, resp.Gates, len(testService.gates))
	for i, gateKey := range testService.gates {
		require.Equal(t, hex.EncodeToString(gateKey.PublicKey().Bytes()), resp.Gates[i])
	}
}

// Credentials may be issued for a gateway the service knows nothing about.
func TestUnconfiguredGate(t *testing.T) {
	testService := newTestApiService(t, 2)

	stranger, err := keys.NewPrivateKey()
	require.NoError(t, err)

	rec, prepared := testService.requestPrepare(t, S3CredentialsRequest{
		Issuer: testService.issuer.EncodeToString(),
		Gates:  []string{hex.EncodeToString(stranger.PublicKey().Bytes())},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec, completed := testService.requestComplete(t, CompleteS3CredentialsRequest{
		State:  prepared.State,
		Tokens: signTokens(t, prepared.Tokens, testService.user),
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	payload, err := base64.StdEncoding.DecodeString(completed.AccessBox)
	require.NoError(t, err)

	var box accessbox.AccessBox
	require.NoError(t, box.Unmarshal(payload))

	resolver := &contracts.NoOpNNSResolver{}

	gateData, err := box.GetTokens(stranger, resolver)
	require.NoError(t, err)
	require.Equal(t, completed.SecretAccessKey, gateData.AccessKey)

	// The configured gateways get nothing from a box that did not ask for them.
	for _, gateKey := range testService.gates {
		_, err = box.GetTokens(gateKey, resolver)
		require.Error(t, err)
	}
}

func TestPrepareValidation(t *testing.T) {
	testService := newTestApiService(t, 2)
	issuer := testService.issuer.EncodeToString()

	t.Run("no issuer", func(t *testing.T) {
		rec, _ := testService.requestPrepare(t, S3CredentialsRequest{})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("malformed issuer", func(t *testing.T) {
		rec, _ := testService.requestPrepare(t, S3CredentialsRequest{Issuer: "definitely not a user id"})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("subset of the configured gates", func(t *testing.T) {
		rec, prepared := testService.requestPrepare(t, S3CredentialsRequest{
			Issuer: issuer,
			Gates:  []string{hex.EncodeToString(testService.gates[1].PublicKey().Bytes())},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		body, err := base64.StdEncoding.DecodeString(prepared.Tokens[0])
		require.NoError(t, err)

		var token session2.Token
		require.NoError(t, token.UnmarshalSignedData(body))
		require.Len(t, token.Subjects(), 1)
	})

	t.Run("malformed gate key", func(t *testing.T) {
		rec, _ := testService.requestPrepare(t, S3CredentialsRequest{Issuer: issuer, Gates: []string{"zz"}})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("contexts", func(t *testing.T) {
		rec, _ := testService.requestPrepare(t, S3CredentialsRequest{
			Issuer:   issuer,
			Contexts: []TokenContext{{Verbs: []TokenVerb{"NO_SUCH_VERB"}}},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "unknown session token verb")

		rec, _ = testService.requestPrepare(t, S3CredentialsRequest{
			Issuer:   issuer,
			Contexts: []TokenContext{{ContainerID: "not a container"}},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)

		rec, _ = testService.requestPrepare(t, S3CredentialsRequest{
			Issuer:   issuer,
			Contexts: []TokenContext{{Verbs: nil}},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "at least one verb")

		rec, _ = testService.requestPrepare(t, S3CredentialsRequest{
			Issuer: issuer,
			Contexts: []TokenContext{
				{ContainerID: testContainerID, Verbs: []TokenVerb{VerbObjectGet}},
				{ContainerID: testContainerID, Verbs: []TokenVerb{VerbObjectPut}},
			},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "same container")
	})

	t.Run("explicit contexts", func(t *testing.T) {
		rec, prepared := testService.requestPrepare(t, S3CredentialsRequest{
			Issuer: issuer,
			Contexts: []TokenContext{
				{Verbs: []TokenVerb{VerbObjectGet, VerbObjectHead}},
				{ContainerID: testContainerID, Verbs: []TokenVerb{VerbObjectPut, VerbObjectDelete}},
			},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		body, err := base64.StdEncoding.DecodeString(prepared.Tokens[0])
		require.NoError(t, err)

		var token session2.Token
		require.NoError(t, token.UnmarshalSignedData(body))
		require.Len(t, token.Contexts(), 2)

		var cnrID cid.ID
		require.NoError(t, cnrID.DecodeString(testContainerID))
		require.True(t, token.AssertVerb(session2.VerbObjectPut, cnrID))
		require.False(t, token.AssertVerb(session2.VerbObjectPut, cid.ID{1, 2, 3}))
		require.True(t, token.AssertVerb(session2.VerbObjectGet, cid.ID{1, 2, 3}))
	})

	t.Run("expiration", func(t *testing.T) {
		past := "2000-01-01T00:00:00Z"
		rec, _ := testService.requestPrepare(t, S3CredentialsRequest{Issuer: issuer, ExpirationRfc3339: &past})
		require.Equal(t, http.StatusBadRequest, rec.Code)

		malformed := "yesterday"
		rec, _ = testService.requestPrepare(t, S3CredentialsRequest{Issuer: issuer, ExpirationRfc3339: &malformed})
		require.Equal(t, http.StatusBadRequest, rec.Code)

		tooLong := "10000h"
		rec, _ = testService.requestPrepare(t, S3CredentialsRequest{Issuer: issuer, ExpirationDuration: &tooLong})
		require.Equal(t, http.StatusBadRequest, rec.Code)

		stale := int(time.Now().Add(-time.Hour).Unix())
		rec, _ = testService.requestPrepare(t, S3CredentialsRequest{Issuer: issuer, ExpirationTimestamp: &stale})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("expiration precedence", func(t *testing.T) {
		var (
			rfc3339   = time.Now().Add(100 * time.Hour).UTC().Format(time.RFC3339)
			timestamp = int(time.Now().Add(200 * time.Hour).Unix())
			duration  = "300h"
		)

		// Later fields override earlier ones: rfc3339, timestamp, duration.
		rec, prepared := testService.requestPrepare(t, S3CredentialsRequest{
			Issuer:              issuer,
			ExpirationRfc3339:   &rfc3339,
			ExpirationTimestamp: &timestamp,
			ExpirationDuration:  &duration,
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		expiresAt, err := time.Parse(time.RFC3339, prepared.ExpiresAt)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(300*time.Hour), expiresAt, time.Minute)

		rec, prepared = testService.requestPrepare(t, S3CredentialsRequest{
			Issuer:              issuer,
			ExpirationRfc3339:   &rfc3339,
			ExpirationTimestamp: &timestamp,
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		expiresAt, err = time.Parse(time.RFC3339, prepared.ExpiresAt)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(200*time.Hour), expiresAt, time.Minute)
	})
}

func requestPrepare(t *testing.T, testService *testApiService) S3CredentialsResponse {
	t.Helper()

	rec, resp := testService.requestPrepare(t, S3CredentialsRequest{Issuer: testService.issuer.EncodeToString()})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	return resp
}

func TestCompleteValidation(t *testing.T) {
	testService := newTestApiService(t, 2)

	t.Run("malformed state", func(t *testing.T) {
		p := requestPrepare(t, testService)

		rec, _ := testService.requestComplete(t, CompleteS3CredentialsRequest{
			State:  "not a state",
			Tokens: signTokens(t, p.Tokens, testService.user),
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("no tokens", func(t *testing.T) {
		p := requestPrepare(t, testService)

		rec, _ := testService.requestComplete(t, CompleteS3CredentialsRequest{State: p.State})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("wrong signer", func(t *testing.T) {
		p := requestPrepare(t, testService)

		stranger, err := keys.NewPrivateKey()
		require.NoError(t, err)

		rec, _ := testService.requestComplete(t, CompleteS3CredentialsRequest{
			State:  p.State,
			Tokens: signTokens(t, p.Tokens, stranger),
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "not by the issuer")
	})

	t.Run("broken signature", func(t *testing.T) {
		p := requestPrepare(t, testService)

		signed := signTokens(t, p.Tokens, testService.user)
		signed[0].Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))

		rec, _ := testService.requestComplete(t, CompleteS3CredentialsRequest{State: p.State, Tokens: signed})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "invalid signature")
	})

	t.Run("unknown scheme", func(t *testing.T) {
		p := requestPrepare(t, testService)

		signed := signTokens(t, p.Tokens, testService.user)
		signed[0].Scheme = "rot13"

		rec, _ := testService.requestComplete(t, CompleteS3CredentialsRequest{State: p.State, Tokens: signed})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("container policies", func(t *testing.T) {
		p := requestPrepare(t, testService)

		rec, completed := testService.requestComplete(t, CompleteS3CredentialsRequest{
			State:             p.State,
			Tokens:            signTokens(t, p.Tokens, testService.user),
			ContainerPolicies: map[string]string{"rep-3": "REP 3"},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		payload, err := base64.StdEncoding.DecodeString(completed.AccessBox)
		require.NoError(t, err)

		var box accessbox.AccessBox
		require.NoError(t, box.Unmarshal(payload))

		policies, err := box.GetPlacementPolicy()
		require.NoError(t, err)
		require.Len(t, policies, 1)
		require.Equal(t, "rep-3", policies[0].LocationConstraint)
	})

	t.Run("malformed container policies", func(t *testing.T) {
		p := requestPrepare(t, testService)

		rec, _ := testService.requestComplete(t, CompleteS3CredentialsRequest{
			State:             p.State,
			Tokens:            signTokens(t, p.Tokens, testService.user),
			ContainerPolicies: map[string]string{"nonsense": "NOT A POLICY"},
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("access box too big", func(t *testing.T) {
		// 512 gates need more than the 64 KB an S3 gateway is willing to read.
		testService := newTestApiService(t, 512)

		rec, p := testService.requestPrepare(t, S3CredentialsRequest{Issuer: testService.issuer.EncodeToString()})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		rec, _ = testService.requestComplete(t, CompleteS3CredentialsRequest{
			State:  p.State,
			Tokens: signTokens(t, p.Tokens, testService.user),
		})
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "too big")
	})
}
