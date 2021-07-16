package authmate

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/netmap"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/session"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-node/pkg/policy"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"go.uber.org/zap"
)

const (
	defaultAuthContainerBasicACL uint32 = 0b00111100100011001000110011001110
)

// Agent contains client communicating with NeoFS and logger.
type Agent struct {
	pool pool.Pool
	log  *zap.Logger
}

// New creates an object of type Agent that consists of Client and logger.
func New(log *zap.Logger, conns pool.Pool) *Agent {
	return &Agent{log: log, pool: conns}
}

type (
	// IssueSecretOptions contains options for passing to Agent.IssueSecret method.
	IssueSecretOptions struct {
		ContainerID           *cid.ID
		ContainerFriendlyName string
		NeoFSKey              *keys.PrivateKey
		GatesPublicKeys       []*keys.PublicKey
		EACLRules             []byte
		ContextRules          []byte
		SessionTkn            bool
		Lifetime              uint64
	}

	// ObtainSecretOptions contains options for passing to Agent.ObtainSecret method.
	ObtainSecretOptions struct {
		SecretAddress  string
		GatePrivateKey *keys.PrivateKey
	}
)

// lifetimeOptions holds NeoFS epochs, iat -- epoch, which a token was issued at, exp -- epoch, when the token expires.
type lifetimeOptions struct {
	Iat uint64
	Exp uint64
}

type (
	issuingResult struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		OwnerPrivateKey string `json:"owner_private_key"`
		ContainerID     string `json:"container_id"`
	}

	obtainingResult struct {
		BearerToken     *token.BearerToken `json:"-"`
		SecretAccessKey string             `json:"secret_access_key"`
	}
)

func (a *Agent) checkContainer(ctx context.Context, cid *cid.ID, friendlyName string) (*cid.ID, error) {
	if cid != nil {
		// check that container exists
		_, err := a.pool.GetContainer(ctx, cid)
		return cid, err
	}

	pp, err := buildPlacementPolicy("")
	if err != nil {
		return nil, fmt.Errorf("failed to build placement policy: %w", err)
	}

	cnr := container.New(
		container.WithPolicy(pp),
		container.WithCustomBasicACL(defaultAuthContainerBasicACL),
		container.WithAttribute(container.AttributeName, friendlyName),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)))

	cid, err = a.pool.PutContainer(ctx, cnr)
	if err != nil {
		return nil, err
	}

	if err := a.pool.WaitForContainerPresence(ctx, cid, pool.DefaultPollingParams()); err != nil {
		return nil, err
	}
	return cid, nil
}

func (a *Agent) getCurrentEpoch(ctx context.Context) (uint64, error) {
	if conn, _, err := a.pool.Connection(); err != nil {
		return 0, err
	} else if networkInfo, err := conn.NetworkInfo(ctx); err != nil {
		return 0, err
	} else {
		return networkInfo.CurrentEpoch(), nil
	}
}

// IssueSecret creates an auth token, puts it in the NeoFS network and writes to io.Writer a new secret access key.
func (a *Agent) IssueSecret(ctx context.Context, w io.Writer, options *IssueSecretOptions) error {
	var (
		err      error
		cid      *cid.ID
		box      *accessbox.AccessBox
		lifetime lifetimeOptions
	)

	lifetime.Iat, err = a.getCurrentEpoch(ctx)
	if err != nil {
		return err
	}

	if options.Lifetime >= math.MaxUint64-lifetime.Iat {
		lifetime.Exp = math.MaxUint64
	} else {
		lifetime.Exp = lifetime.Iat + options.Lifetime
	}

	a.log.Info("check container", zap.Stringer("cid", options.ContainerID))
	if cid, err = a.checkContainer(ctx, options.ContainerID, options.ContainerFriendlyName); err != nil {
		return err
	}

	gatesData, err := createTokens(options, lifetime, cid)
	if err != nil {
		return fmt.Errorf("failed to build bearer token: %w", err)
	}

	box, secrets, err := accessbox.PackTokens(gatesData)
	if err != nil {
		return err
	}

	oid, err := ownerIDFromNeoFSKey(options.NeoFSKey.PublicKey())
	if err != nil {
		return err
	}

	a.log.Info("store bearer token into NeoFS",
		zap.Stringer("owner_tkn", oid))

	if !options.SessionTkn && len(options.ContextRules) > 0 {
		_, err := w.Write([]byte("Warning: rules for session token were set but --create-session flag wasn't, " +
			"so session token was not created\n"))
		if err != nil {
			return err
		}
	}

	address, err := tokens.
		New(a.pool, secrets.EphemeralKey).
		Put(ctx, cid, oid, box, options.GatesPublicKeys...)
	if err != nil {
		return fmt.Errorf("failed to put bearer token: %w", err)
	}

	accessKeyID := address.ContainerID().String() + "0" + address.ObjectID().String()

	ir := &issuingResult{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secrets.AccessKey,
		OwnerPrivateKey: hex.EncodeToString(secrets.EphemeralKey.Bytes()),
		ContainerID:     cid.String(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ir)
}

// ObtainSecret receives an existing secret access key from NeoFS and
// writes to io.Writer the secret access key.
func (a *Agent) ObtainSecret(ctx context.Context, w io.Writer, options *ObtainSecretOptions) error {
	bearerCreds := tokens.New(a.pool, options.GatePrivateKey)
	address := object.NewAddress()
	if err := address.Parse(options.SecretAddress); err != nil {
		return fmt.Errorf("failed to parse secret address: %w", err)
	}

	tkns, err := bearerCreds.GetTokens(ctx, address)
	if err != nil {
		return fmt.Errorf("failed to get tokens: %w", err)
	}

	or := &obtainingResult{
		BearerToken:     tkns.BearerToken,
		SecretAccessKey: tkns.AccessKey,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(or)
}

func buildPlacementPolicy(placementRules string) (*netmap.PlacementPolicy, error) {
	if len(placementRules) != 0 {
		return policy.Parse(placementRules)
	}

	/*
		REP 1 IN X 			  // place one copy of object
		CBF 1
		SELECT 2 From * AS X  // in container of two nodes
	*/
	pp := new(netmap.PlacementPolicy)
	pp.SetContainerBackupFactor(1)
	pp.SetReplicas([]*netmap.Replica{newReplica("X", 1)}...)
	pp.SetSelectors([]*netmap.Selector{newSimpleSelector("X", 2)}...)

	return pp, nil
}

// selects <count> nodes in container without any additional attributes.
func newSimpleSelector(name string, count uint32) (s *netmap.Selector) {
	s = new(netmap.Selector)
	s.SetCount(count)
	s.SetFilter("*")
	s.SetName(name)
	return
}

func newReplica(name string, count uint32) (r *netmap.Replica) {
	r = new(netmap.Replica)
	r.SetCount(count)
	r.SetSelector(name)
	return
}

func buildEACLTable(cid *cid.ID, eaclTable []byte) (*eacl.Table, error) {
	table := eacl.NewTable()
	if len(eaclTable) != 0 {
		return table, table.UnmarshalJSON(eaclTable)
	}

	record := eacl.NewRecord()
	record.SetOperation(eacl.OperationGet)
	record.SetAction(eacl.ActionAllow)
	// TODO: Change this later.
	// from := eacl.HeaderFromObject
	// matcher := eacl.MatchStringEqual
	// record.AddFilter(from eacl.FilterHeaderType, matcher eacl.Match, name string, value string)
	eacl.AddFormedTarget(record, eacl.RoleOthers)
	table.SetCID(cid)
	table.AddRecord(record)

	return table, nil
}

func buildContext(rules []byte) (*session.ContainerContext, error) {
	sessionCtx := session.NewContainerContext() // wildcard == true on by default

	if len(rules) != 0 {
		// cast ToV2 temporary, because there is no method for unmarshalling in ContainerContext in api-go
		err := sessionCtx.UnmarshalJSON(rules)
		if err != nil {
			return nil, fmt.Errorf("failed to read rules for session token: %w", err)
		}
		return sessionCtx, nil
	}
	sessionCtx.ForPut()
	sessionCtx.ApplyTo(nil)
	return sessionCtx, nil
}

func buildBearerToken(key *keys.PrivateKey, table *eacl.Table, lifetime lifetimeOptions, gateKey *keys.PublicKey) (*token.BearerToken, error) {
	oid, err := ownerIDFromNeoFSKey(gateKey)
	if err != nil {
		return nil, err
	}

	bearerToken := token.NewBearerToken()
	bearerToken.SetEACLTable(table)
	bearerToken.SetOwner(oid)
	bearerToken.SetLifetime(lifetime.Exp, lifetime.Iat, lifetime.Iat)

	return bearerToken, bearerToken.SignToken(&key.PrivateKey)
}

func buildBearerTokens(key *keys.PrivateKey, table *eacl.Table, lifetime lifetimeOptions, gatesKeys []*keys.PublicKey) ([]*token.BearerToken, error) {
	bearerTokens := make([]*token.BearerToken, 0, len(gatesKeys))
	for _, gateKey := range gatesKeys {
		tkn, err := buildBearerToken(key, table, lifetime, gateKey)
		if err != nil {
			return nil, err
		}
		bearerTokens = append(bearerTokens, tkn)
	}
	return bearerTokens, nil
}

func buildSessionToken(key *keys.PrivateKey, oid *owner.ID, lifetime lifetimeOptions, ctx *session.ContainerContext, gateKey *keys.PublicKey) (*session.Token, error) {
	tok := session.NewToken()
	tok.SetContext(ctx)
	uid, err := uuid.New().MarshalBinary()
	if err != nil {
		return nil, err
	}
	tok.SetID(uid)
	tok.SetOwnerID(oid)
	tok.SetSessionKey(gateKey.Bytes())

	tok.SetIat(lifetime.Iat)
	tok.SetNbf(lifetime.Iat)
	tok.SetExp(lifetime.Exp)

	return tok, tok.Sign(&key.PrivateKey)
}

func buildSessionTokens(key *keys.PrivateKey, oid *owner.ID, lifetime lifetimeOptions, ctx *session.ContainerContext, gatesKeys []*keys.PublicKey) ([]*session.Token, error) {
	sessionTokens := make([]*session.Token, 0, len(gatesKeys))
	for _, gateKey := range gatesKeys {
		tkn, err := buildSessionToken(key, oid, lifetime, ctx, gateKey)
		if err != nil {
			return nil, err
		}
		sessionTokens = append(sessionTokens, tkn)
	}
	return sessionTokens, nil
}

func createTokens(options *IssueSecretOptions, lifetime lifetimeOptions, cid *cid.ID) ([]*accessbox.GateData, error) {
	gates := make([]*accessbox.GateData, len(options.GatesPublicKeys))

	table, err := buildEACLTable(cid, options.EACLRules)
	if err != nil {
		return nil, fmt.Errorf("failed to build eacl table: %w", err)
	}
	bearerTokens, err := buildBearerTokens(options.NeoFSKey, table, lifetime, options.GatesPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to build bearer tokens: %w", err)
	}
	for i, gateKey := range options.GatesPublicKeys {
		gates[i] = accessbox.NewGateData(gateKey, bearerTokens[i])
	}

	if options.SessionTkn {
		sessionRules, err := buildContext(options.ContextRules)
		if err != nil {
			return nil, fmt.Errorf("failed to build context for session token: %w", err)
		}
		oid, err := ownerIDFromNeoFSKey(options.NeoFSKey.PublicKey())
		if err != nil {
			return nil, err
		}

		sessionTokens, err := buildSessionTokens(options.NeoFSKey, oid, lifetime, sessionRules, options.GatesPublicKeys)
		if err != nil {
			return nil, err
		}
		for i, sessionToken := range sessionTokens {
			gates[i].SessionToken = sessionToken
		}
	}

	return gates, nil
}

func ownerIDFromNeoFSKey(key *keys.PublicKey) (*owner.ID, error) {
	wallet, err := owner.NEO3WalletFromPublicKey((*ecdsa.PublicKey)(key))
	if err != nil {
		return nil, err
	}
	return owner.NewIDFromNeo3Wallet(wallet), nil
}
