package authmate

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/policy"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"go.uber.org/zap"
)

// PrmContainerCreate groups parameters of containers created by authmate.
type PrmContainerCreate struct {
	// NeoFS identifier of the container creator.
	Owner user.ID

	// Container placement policy.
	Policy netmap.PlacementPolicy

	// Friendly name for the container (optional).
	FriendlyName string
}

// NetworkState represents NeoFS network state which is needed for authmate processing.
type NetworkState struct {
	// Current NeoFS time.
	Epoch uint64
	// Duration of the Morph chain block in ms.
	BlockDuration int64
	// Duration of the NeoFS epoch in Morph chain blocks.
	EpochDuration uint64
}

// NeoFS represents virtual connection to NeoFS network.
type NeoFS interface {
	// NeoFS interface required by credential tool.
	tokens.NeoFS

	// ContainerExists checks container presence in NeoFS by identifier.
	// Returns nil if container exists.
	ContainerExists(context.Context, cid.ID) error

	// CreateContainer creates and saves parameterized container in NeoFS.
	// It sets 'Timestamp' attribute to the current time.
	// It returns the ID of the saved container.
	//
	// The container must be private with GET access for OTHERS group.
	// Creation time should also be stamped.
	//
	// It returns exactly one non-nil value. It returns any error encountered which
	// prevented the container from being created.
	CreateContainer(context.Context, PrmContainerCreate) (*cid.ID, error)

	// TimeToEpoch computes the current epoch and the epoch that corresponds to the provided time.
	// Note:
	// * time must be in the future
	// * time will be ceil rounded to match epoch
	//
	// It returns any error encountered which prevented computing epochs.
	TimeToEpoch(context.Context, time.Time) (uint64, uint64, error)
}

// Agent contains client communicating with NeoFS and logger.
type Agent struct {
	neoFS NeoFS
	log   *zap.Logger
}

// New creates an object of type Agent that consists of Client and logger.
func New(log *zap.Logger, neoFS NeoFS) *Agent {
	return &Agent{log: log, neoFS: neoFS}
}

type (
	// ContainerPolicies contains mapping of aws LocationConstraint to neofs PlacementPolicy.
	ContainerPolicies map[string]string

	// IssueSecretOptions contains options for passing to Agent.IssueSecret method.
	IssueSecretOptions struct {
		Container             ContainerOptions
		NeoFSKey              *keys.PrivateKey
		GatesPublicKeys       []*keys.PublicKey
		EACLRules             []byte
		SessionTokenRules     []byte
		SkipSessionRules      bool
		Lifetime              time.Duration
		AwsCliCredentialsFile string
		ContainerPolicies     ContainerPolicies
	}

	// ContainerOptions groups parameters of auth container to put the secret into.
	ContainerOptions struct {
		ID              *cid.ID
		FriendlyName    string
		PlacementPolicy string
	}

	// ObtainSecretOptions contains options for passing to Agent.ObtainSecret method.
	ObtainSecretOptions struct {
		SecretAddress  string
		GatePrivateKey *keys.PrivateKey
	}
)

// lifetimeOptions holds NeoFS epochs, iat -- epoch which the token was issued at, exp -- epoch when the token expires.
type lifetimeOptions struct {
	Iat uint64
	Exp uint64
}

type (
	issuingResult struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		OwnerPrivateKey string `json:"owner_private_key"`
		WalletPublicKey string `json:"wallet_public_key"`
		ContainerID     string `json:"container_id"`
	}

	obtainingResult struct {
		BearerToken     *bearer.Token `json:"-"`
		SecretAccessKey string        `json:"secret_access_key"`
	}
)

func (a *Agent) checkContainer(ctx context.Context, opts ContainerOptions, idOwner user.ID) (*cid.ID, error) {
	if opts.ID != nil {
		// check that the container exists
		return opts.ID, a.neoFS.ContainerExists(ctx, *opts.ID)
	}

	pp, err := policy.Parse(opts.PlacementPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to build placement policy: %w", err)
	}

	cnrID, err := a.neoFS.CreateContainer(ctx, PrmContainerCreate{
		Owner:        idOwner,
		Policy:       *pp,
		FriendlyName: opts.FriendlyName,
	})
	if err != nil {
		return nil, err
	}

	return cnrID, nil
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
		box      *accessbox.AccessBox
		lifetime lifetimeOptions
	)

	policies, err := preparePolicy(options.ContainerPolicies)
	if err != nil {
		return err
	}

	lifetime.Iat, lifetime.Exp, err = a.neoFS.TimeToEpoch(ctx, time.Now().Add(options.Lifetime))
	if err != nil {
		return err
	}

	gatesData, err := createTokens(options, lifetime)
	if err != nil {
		return err
	}

	box, secrets, err := accessbox.PackTokens(gatesData)
	if err != nil {
		return err
	}

	box.ContainerPolicy = policies

	var idOwner user.ID
	user.IDFromKey(&idOwner, options.NeoFSKey.PrivateKey.PublicKey)

	a.log.Info("check container or create", zap.Stringer("cid", options.Container.ID),
		zap.String("friendly_name", options.Container.FriendlyName),
		zap.String("placement_policy", options.Container.PlacementPolicy))
	id, err := a.checkContainer(ctx, options.Container, idOwner)
	if err != nil {
		return err
	}

	a.log.Info("store bearer token into NeoFS",
		zap.Stringer("owner_tkn", idOwner))

	addr, err := tokens.
		New(a.neoFS, secrets.EphemeralKey, cache.DefaultAccessBoxConfig()).
		Put(ctx, *id, idOwner, box, lifetime.Exp, options.GatesPublicKeys...)
	if err != nil {
		return fmt.Errorf("failed to put bearer token: %w", err)
	}

	objID := addr.Object()
	strIDObj := objID.EncodeToString()

	accessKeyID := addr.Container().EncodeToString() + "0" + strIDObj

	ir := &issuingResult{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secrets.AccessKey,
		OwnerPrivateKey: hex.EncodeToString(secrets.EphemeralKey.Bytes()),
		WalletPublicKey: hex.EncodeToString(options.NeoFSKey.PublicKey().Bytes()),
		ContainerID:     id.EncodeToString(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err = enc.Encode(ir); err != nil {
		return err
	}

	if options.AwsCliCredentialsFile != "" {
		profileName := "authmate_cred_" + strIDObj
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
	bearerCreds := tokens.New(a.neoFS, options.GatePrivateKey, cache.DefaultAccessBoxConfig())

	var addr oid.Address
	if err := addr.DecodeString(options.SecretAddress); err != nil {
		return fmt.Errorf("failed to parse secret address: %w", err)
	}

	box, err := bearerCreds.GetBox(ctx, addr)
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

func buildEACLTable(eaclTable []byte) (*eacl.Table, error) {
	if len(eaclTable) != 0 {
		// fixme(neofs-sdk-go/#235)
		// Can't parse SDK version of eACL table because it requires
		// non-empty container ID. Possible solution: read json of bearer
		// token instead of eACL table.
		v2table := new(v2acl.Table)
		err := v2table.UnmarshalJSON(eaclTable)
		if err != nil {
			return nil, err
		}
		return eacl.NewTableFromV2(v2table), nil
	}

	table := eacl.NewTable()
	record := eacl.NewRecord()
	record.SetOperation(eacl.OperationGet)
	record.SetAction(eacl.ActionAllow)
	eacl.AddFormedTarget(record, eacl.RoleOthers)
	table.AddRecord(record)

	for _, rec := range restrictedRecords() {
		table.AddRecord(rec)
	}

	return table, nil
}

func restrictedRecords() (records []*eacl.Record) {
	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		record := eacl.NewRecord()
		record.SetOperation(op)
		record.SetAction(eacl.ActionDeny)
		eacl.AddFormedTarget(record, eacl.RoleOthers)
		records = append(records, record)
	}

	return
}

func buildBearerToken(key *keys.PrivateKey, table *eacl.Table, lifetime lifetimeOptions, gateKey *keys.PublicKey) (*bearer.Token, error) {
	var ownerID user.ID
	user.IDFromKey(&ownerID, (ecdsa.PublicKey)(*gateKey))

	var bearerToken bearer.Token
	bearerToken.SetEACLTable(*table)
	bearerToken.SetOwnerID(ownerID)
	bearerToken.SetExpiration(lifetime.Exp)
	bearerToken.SetIssuedAt(lifetime.Iat)
	bearerToken.SetNotBefore(lifetime.Iat)

	return &bearerToken, bearerToken.Sign(key.PrivateKey)
}

func buildBearerTokens(key *keys.PrivateKey, table *eacl.Table, lifetime lifetimeOptions, gatesKeys []*keys.PublicKey) ([]*bearer.Token, error) {
	bearerTokens := make([]*bearer.Token, 0, len(gatesKeys))
	for _, gateKey := range gatesKeys {
		tkn, err := buildBearerToken(key, table, lifetime, gateKey)
		if err != nil {
			return nil, err
		}
		bearerTokens = append(bearerTokens, tkn)
	}
	return bearerTokens, nil
}

func buildSessionToken(key *keys.PrivateKey, lifetime lifetimeOptions, ctx sessionTokenContext, gateKey *keys.PublicKey) (*session.Container, error) {
	tok := new(session.Container)
	tok.ForVerb(ctx.verb)
	if ctx.containerID != nil {
		tok.AppliedTo(*ctx.containerID)
	}

	tok.SetID(uuid.New())
	tok.SetAuthKey((*neofsecdsa.PublicKey)(gateKey))

	tok.SetIat(lifetime.Iat)
	tok.SetNbf(lifetime.Iat)
	tok.SetExp(lifetime.Exp)

	return tok, tok.Sign(key.PrivateKey)
}

func buildSessionTokens(key *keys.PrivateKey, lifetime lifetimeOptions, ctxs []sessionTokenContext, gatesKeys []*keys.PublicKey) ([][]*session.Container, error) {
	sessionTokens := make([][]*session.Container, 0, len(gatesKeys))
	for _, gateKey := range gatesKeys {
		tkns := make([]*session.Container, len(ctxs))
		for i, ctx := range ctxs {
			tkn, err := buildSessionToken(key, lifetime, ctx, gateKey)
			if err != nil {
				return nil, err
			}
			tkns[i] = tkn
		}
		sessionTokens = append(sessionTokens, tkns)
	}
	return sessionTokens, nil
}

func createTokens(options *IssueSecretOptions, lifetime lifetimeOptions) ([]*accessbox.GateData, error) {
	gates := make([]*accessbox.GateData, len(options.GatesPublicKeys))

	table, err := buildEACLTable(options.EACLRules)
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

	if !options.SkipSessionRules {
		sessionRules, err := buildContext(options.SessionTokenRules)
		if err != nil {
			return nil, fmt.Errorf("failed to build context for session token: %w", err)
		}

		sessionTokens, err := buildSessionTokens(options.NeoFSKey, lifetime, sessionRules, options.GatesPublicKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to biuild session token: %w", err)
		}
		for i, sessionTkns := range sessionTokens {
			gates[i].SessionTokens = sessionTkns
		}
	}

	return gates, nil
}
