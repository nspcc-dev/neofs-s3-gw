package authmate

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/acl"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/owner"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/token"
	"go.uber.org/zap"
)

const (
	defaultAuthContainerBasicACL acl.BasicACL = 0b00111100100011001000110011001110 // 0x3C8C8CCE - private container with only GET allowed to others
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
	// ContainerPolicies contains mapping of aws LocationConstraint to neofs PlacementPolicy.
	ContainerPolicies map[string]string

	// IssueSecretOptions contains options for passing to Agent.IssueSecret method.
	IssueSecretOptions struct {
		ContainerID           *cid.ID
		ContainerFriendlyName string
		NeoFSKey              *keys.PrivateKey
		GatesPublicKeys       []*keys.PublicKey
		EACLRules             []byte
		SessionTokenRules     []byte
		Lifetime              time.Duration
		AwsCliCredentialsFile string
		ContainerPolicies     ContainerPolicies
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

type epochDurations struct {
	currentEpoch  uint64
	msPerBlock    int64
	blocksInEpoch uint64
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

	cnrOptions := []container.Option{
		container.WithPolicy(pp),
		container.WithCustomBasicACL(defaultAuthContainerBasicACL),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)),
	}
	if friendlyName != "" {
		cnrOptions = append(cnrOptions, container.WithAttribute(container.AttributeName, friendlyName))
	}

	cnr := container.New(cnrOptions...)
	if friendlyName != "" {
		container.SetNativeName(cnr, friendlyName)
	}

	cid, err = a.pool.PutContainer(ctx, cnr)
	if err != nil {
		return nil, err
	}

	if err := a.pool.WaitForContainerPresence(ctx, cid, pool.DefaultPollingParams()); err != nil {
		return nil, err
	}
	return cid, nil
}

func (a *Agent) getEpochDurations(ctx context.Context) (*epochDurations, error) {
	if conn, _, err := a.pool.Connection(); err != nil {
		return nil, err
	} else if networkInfoRes, err := conn.NetworkInfo(ctx); err != nil {
		return nil, err
	} else if err = apistatus.ErrFromStatus(networkInfoRes.Status()); err != nil {
		return nil, err
	} else {
		networkInfo := networkInfoRes.Info()
		res := &epochDurations{
			currentEpoch: networkInfo.CurrentEpoch(),
			msPerBlock:   networkInfo.MsPerBlock(),
		}

		networkInfo.NetworkConfig().IterateParameters(func(parameter *netmap.NetworkParameter) bool {
			if string(parameter.Key()) == "EpochDuration" {
				data := make([]byte, 8)
				copy(data, parameter.Value())
				res.blocksInEpoch = binary.LittleEndian.Uint64(data)
				return true
			}
			return false
		})
		if res.blocksInEpoch == 0 {
			return nil, fmt.Errorf("not found param: EpochDuration")
		}
		return res, nil
	}
}

func checkPolicy(policyString string) (*netmap.PlacementPolicy, error) {
	result, err := policy.Parse(policyString)
	if err == nil {
		return result, nil
	}

	result = netmap.NewPlacementPolicy()
	if err = result.UnmarshalJSON([]byte(policyString)); err == nil {
		return result, nil
	}

	return nil, fmt.Errorf("can't parse placement policy")
}

func preparePolicy(policy ContainerPolicies) ([]*accessbox.AccessBox_ContainerPolicy, error) {
	if policy == nil {
		return nil, nil
	}

	var result []*accessbox.AccessBox_ContainerPolicy
	for locationConstraint, placementPolicy := range policy {
		parsedPolicy, err := checkPolicy(placementPolicy)
		if err != nil {
			return nil, err
		}
		marshaled, err := parsedPolicy.Marshal()
		if err != nil {
			return nil, fmt.Errorf("can't marshal placement policy: %w", err)
		}

		result = append(result, &accessbox.AccessBox_ContainerPolicy{
			LocationConstraint: locationConstraint,
			Policy:             marshaled,
		})
	}

	return result, nil
}

// IssueSecret creates an auth token, puts it in the NeoFS network and writes to io.Writer a new secret access key.
func (a *Agent) IssueSecret(ctx context.Context, w io.Writer, options *IssueSecretOptions) error {
	var (
		err      error
		cid      *cid.ID
		box      *accessbox.AccessBox
		lifetime lifetimeOptions
	)

	policies, err := preparePolicy(options.ContainerPolicies)
	if err != nil {
		return err
	}

	durations, err := a.getEpochDurations(ctx)
	if err != nil {
		return err
	}
	lifetime.Iat = durations.currentEpoch
	msPerEpoch := durations.blocksInEpoch * uint64(durations.msPerBlock)
	epochLifetime := uint64(options.Lifetime.Milliseconds()) / msPerEpoch
	if uint64(options.Lifetime.Milliseconds())%msPerEpoch != 0 {
		epochLifetime++
	}

	if epochLifetime >= math.MaxUint64-lifetime.Iat {
		lifetime.Exp = math.MaxUint64
	} else {
		lifetime.Exp = lifetime.Iat + epochLifetime
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

	box.ContainerPolicy = policies

	oid := owner.NewIDFromPublicKey(&options.NeoFSKey.PrivateKey.PublicKey)

	a.log.Info("store bearer token into NeoFS",
		zap.Stringer("owner_tkn", oid))

	address, err := tokens.
		New(a.pool, secrets.EphemeralKey, cache.DefaultAccessBoxConfig()).
		Put(ctx, cid, oid, box, lifetime.Exp, options.GatesPublicKeys...)
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
	if err = enc.Encode(ir); err != nil {
		return err
	}

	if options.AwsCliCredentialsFile != "" {
		profileName := "authmate_cred_" + address.ObjectID().String()
		if _, err = os.Stat(options.AwsCliCredentialsFile); os.IsNotExist(err) {
			profileName = "default"
		}
		file, err := os.OpenFile(options.AwsCliCredentialsFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("couldn't open aws cli credentials file: %w", err)
		}
		defer file.Close()
		if _, err = file.WriteString(fmt.Sprintf("\n[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
			profileName, accessKeyID, secrets.AccessKey)); err != nil {
			return err
		}
	}
	return nil
}

// ObtainSecret receives an existing secret access key from NeoFS and
// writes to io.Writer the secret access key.
func (a *Agent) ObtainSecret(ctx context.Context, w io.Writer, options *ObtainSecretOptions) error {
	bearerCreds := tokens.New(a.pool, options.GatePrivateKey, cache.DefaultAccessBoxConfig())
	address := object.NewAddress()
	if err := address.Parse(options.SecretAddress); err != nil {
		return fmt.Errorf("failed to parse secret address: %w", err)
	}

	box, err := bearerCreds.GetBox(ctx, address)
	if err != nil {
		return fmt.Errorf("failed to get tokens: %w", err)
	}

	or := &obtainingResult{
		BearerToken:     box.Gate.BearerToken,
		SecretAccessKey: box.Gate.AccessKey,
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
		REP 2 IN X 			  // place two copies of object
		CBF 3
		SELECT 2 From * AS X  // in container of two nodes
	*/
	pp := new(netmap.PlacementPolicy)
	pp.SetContainerBackupFactor(3)
	pp.SetReplicas([]*netmap.Replica{newReplica("X", 2)}...)
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

func buildContext(rules []byte) ([]*session.ContainerContext, error) {
	var sessionCtxs []*session.ContainerContext

	if len(rules) != 0 {
		// cast ToV2 temporary, because there is no method for unmarshalling in ContainerContext in api-go
		err := json.Unmarshal(rules, &sessionCtxs)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules for session token: %w", err)
		}

		var (
			containsPut     = false
			containsSetEACL = false
		)
		for _, s := range sessionCtxs {
			if s.IsForPut() {
				containsPut = true
			} else if s.IsForSetEACL() {
				containsSetEACL = true
			}
		}
		if containsPut && !containsSetEACL {
			ectx := session.NewContainerContext()
			ectx.ForSetEACL()
			sessionCtxs = append(sessionCtxs, ectx)
		}

		return sessionCtxs, nil
	}

	sessionCtxPut := session.NewContainerContext()
	sessionCtxPut.ForPut()

	sessionCtxDelete := session.NewContainerContext()
	sessionCtxDelete.ForDelete()

	sessionCtxEACL := session.NewContainerContext()
	sessionCtxEACL.ForSetEACL()

	return []*session.ContainerContext{sessionCtxPut, sessionCtxDelete, sessionCtxEACL}, nil
}

func buildBearerToken(key *keys.PrivateKey, table *eacl.Table, lifetime lifetimeOptions, gateKey *keys.PublicKey) (*token.BearerToken, error) {
	oid := owner.NewIDFromPublicKey((*ecdsa.PublicKey)(gateKey))

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

func buildSessionTokens(key *keys.PrivateKey, oid *owner.ID, lifetime lifetimeOptions, ctxs []*session.ContainerContext, gatesKeys []*keys.PublicKey) ([][]*session.Token, error) {
	sessionTokens := make([][]*session.Token, 0, len(gatesKeys))
	for _, gateKey := range gatesKeys {
		tkns := make([]*session.Token, len(ctxs))
		for i, ctx := range ctxs {
			tkn, err := buildSessionToken(key, oid, lifetime, ctx, gateKey)
			if err != nil {
				return nil, err
			}
			tkns[i] = tkn
		}
		sessionTokens = append(sessionTokens, tkns)
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

	if options.SessionTokenRules != nil {
		sessionRules, err := buildContext(options.SessionTokenRules)
		if err != nil {
			return nil, fmt.Errorf("failed to build context for session token: %w", err)
		}

		oid := owner.NewIDFromPublicKey(&options.NeoFSKey.PrivateKey.PublicKey)
		sessionTokens, err := buildSessionTokens(options.NeoFSKey, oid, lifetime, sessionRules, options.GatesPublicKeys)
		if err != nil {
			return nil, err
		}
		for i, sessionTkns := range sessionTokens {
			gates[i].SessionTokens = sessionTkns
		}
	}

	return gates, nil
}
