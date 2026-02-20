package authmate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	"github.com/nspcc-dev/neofs-s3-gw/creds/tokens"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	session2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
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
	CreateContainer(context.Context, PrmContainerCreate) (cid.ID, error)

	// TimeToEpoch computes the current epoch and the epoch that corresponds to the provided time.
	// Note:
	// * time must be in the future
	// * time will be ceil rounded to match epoch
	//
	// It returns any error encountered which prevented computing epochs.
	TimeToEpoch(context.Context, time.Time) (uint64, uint64, error)

	// SetContainerEACL updates container EACL.
	SetContainerEACL(ctx context.Context, table eacl.Table, sessionToken *session.Container, sessionTokenV2 *session2.Token) error

	// ContainerEACL gets container EACL.
	ContainerEACL(ctx context.Context, containerID cid.ID) (*eacl.Table, error)
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
		ID              cid.ID
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

	IssuedAt time.Time
	ExpireAt time.Time
}

type (
	issuingResult struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		OwnerPrivateKey string `json:"owner_private_key"`
		WalletPublicKey string `json:"wallet_public_key"`
		ContainerID     string `json:"container_id"`
	}

	// ObtainingResult contains payload for obtainingSecret command.
	ObtainingResult struct {
		BearerToken            *bearer.Token      `json:"-"`
		SessionTokenForSetEACL *session.Container `json:"-"`
		SessionTokenV2         *session2.Token    `json:"-"`
		SecretAccessKey        string             `json:"secret_access_key"`
	}
)

func (a *Agent) checkContainer(ctx context.Context, opts ContainerOptions, idOwner user.ID) (cid.ID, error) {
	if !opts.ID.IsZero() {
		return opts.ID, a.neoFS.ContainerExists(ctx, opts.ID)
	}

	var prm PrmContainerCreate

	err := prm.Policy.DecodeString(opts.PlacementPolicy)
	if err != nil {
		return cid.ID{}, fmt.Errorf("failed to build placement policy: %w", err)
	}

	prm.Owner = idOwner
	prm.FriendlyName = opts.FriendlyName

	cnrID, err := a.neoFS.CreateContainer(ctx, prm)
	if err != nil {
		return cid.ID{}, fmt.Errorf("create container in NeoFS: %w", err)
	}

	return cnrID, nil
}

func checkPolicy(policyString string) (*netmap.PlacementPolicy, error) {
	var result netmap.PlacementPolicy

	err := result.DecodeString(policyString)
	if err == nil {
		return &result, nil
	}

	if err = result.UnmarshalJSON([]byte(policyString)); err == nil {
		return &result, nil
	}

	return nil, errors.New("can't parse placement policy")
}

func preparePolicy(policy ContainerPolicies) ([]*accessbox.AccessBox_ContainerPolicy, error) {
	if policy == nil {
		return nil, nil
	}

	var result []*accessbox.AccessBox_ContainerPolicy
	for locationConstraint, placementPolicy := range policy {
		parsedPolicy, err := checkPolicy(placementPolicy)
		if err != nil {
			return nil, fmt.Errorf("check placement policy: %w", err)
		}

		result = append(result, &accessbox.AccessBox_ContainerPolicy{
			LocationConstraint: locationConstraint,
			Policy:             parsedPolicy.Marshal(),
		})
	}

	return result, nil
}

// IssueSecret creates an auth token, puts it in the NeoFS network and writes to io.Writer a new secret access key.
func (a *Agent) IssueSecret(ctx context.Context, w io.Writer, options *IssueSecretOptions) error {
	var (
		err error
		box *accessbox.AccessBox
		ts  = time.Now()

		lifetime = lifetimeOptions{
			IssuedAt: ts,
			ExpireAt: ts.Add(options.Lifetime),
		}
	)

	policies, err := preparePolicy(options.ContainerPolicies)
	if err != nil {
		return fmt.Errorf("prepare policies: %w", err)
	}

	lifetime.Iat, lifetime.Exp, err = a.neoFS.TimeToEpoch(ctx, time.Now().Add(options.Lifetime))
	if err != nil {
		return fmt.Errorf("fetch time to epoch: %w", err)
	}

	gatesData, err := createTokens(options, lifetime)
	if err != nil {
		return fmt.Errorf("create tokens: %w", err)
	}

	box, secrets, err := accessbox.PackTokens(gatesData)
	if err != nil {
		return fmt.Errorf("pack tokens: %w", err)
	}

	box.ContainerPolicy = policies

	signer := user.NewAutoIDSignerRFC6979(options.NeoFSKey.PrivateKey)
	idOwner := signer.UserID()

	a.log.Info("check container or create", zap.Stringer("cid", options.Container.ID),
		zap.String("friendly_name", options.Container.FriendlyName),
		zap.String("placement_policy", options.Container.PlacementPolicy))
	id, err := a.checkContainer(ctx, options.Container, idOwner)
	if err != nil {
		return fmt.Errorf("check container: %w", err)
	}

	a.log.Info("store bearer token into NeoFS",
		zap.Stringer("owner_tkn", idOwner))

	addr, err := tokens.
		New(a.neoFS, secrets.EphemeralKey, cache.DefaultAccessBoxConfig(a.log)).
		Put(ctx, id, idOwner, box, lifetime.Exp, options.GatesPublicKeys...)
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
		if _, err = fmt.Fprintf(file, "\n[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
			profileName, accessKeyID, secrets.AccessKey); err != nil {
			return fmt.Errorf("fails to write to file: %w", err)
		}
	}
	return nil
}

// ObtainSecret receives an existing secret access key from NeoFS and
// writes to io.Writer the secret access key.
func (a *Agent) ObtainSecret(ctx context.Context, options *ObtainSecretOptions) (*ObtainingResult, error) {
	bearerCreds := tokens.New(a.neoFS, options.GatePrivateKey, cache.DefaultAccessBoxConfig(a.log))

	addr, err := oid.DecodeAddressString(options.SecretAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret address: %w", err)
	}

	box, err := bearerCreds.GetBox(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get tokens: %w", err)
	}

	return &ObtainingResult{
		BearerToken:            box.Gate.BearerToken,
		SecretAccessKey:        box.Gate.AccessKey,
		SessionTokenForSetEACL: box.Gate.SessionTokenForSetEACL(),
		SessionTokenV2:         box.Gate.SessionTokenV2,
	}, nil
}

func buildSessionTokenV2(key *keys.PrivateKey, lifetime lifetimeOptions, contexts []session2.Context, gateKeys []*keys.PublicKey) ([]session2.Token, error) {
	var (
		tokens []session2.Token

		// https://github.com/nspcc-dev/neofs-node/pull/3671#discussion_r2709969518
		tokenIssueTime = lifetime.IssuedAt.Add(-30 * time.Second)
		signer         = user.NewAutoIDSignerRFC6979(key.PrivateKey)
	)

	chunks := slices.Chunk(gateKeys, session2.MaxSubjectsPerToken)

	for keys := range chunks {
		var (
			tokenV2 session2.Token
			targets = make([]session2.Target, 0, len(keys))
		)

		for _, gateKey := range keys {
			targets = append(targets, session2.NewTargetUser(user.NewFromScriptHash(gateKey.GetScriptHash())))
		}

		if err := tokenV2.SetSubjects(targets); err != nil {
			return nil, fmt.Errorf("set subjects: %w", err)
		}

		slices.SortFunc(contexts, func(a, b session2.Context) int {
			return a.Container().Compare(b.Container())
		})

		if err := tokenV2.SetContexts(contexts); err != nil {
			return nil, fmt.Errorf("set contexts: %w", err)
		}

		tokenV2.SetNbf(tokenIssueTime)
		tokenV2.SetIat(tokenIssueTime)
		tokenV2.SetExp(lifetime.ExpireAt)
		tokenV2.SetIssuer(signer.UserID())
		tokenV2.SetVersion(session2.TokenCurrentVersion)

		if err := tokenV2.Sign(signer); err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}

		tokens = append(tokens, tokenV2)
	}

	return tokens, nil
}

func buildSessionTokensV2(key *keys.PrivateKey, lifetime lifetimeOptions, ctxs []sessionTokenContext, gatesKeys []*keys.PublicKey) ([]session2.Token, error) {
	var (
		verbsByCnr = make(map[cid.ID][]session2.Verb)

		objectOperations = []session2.Verb{
			session2.VerbObjectPut,
			session2.VerbObjectGet,
			session2.VerbObjectHead,
			session2.VerbObjectSearch,
			session2.VerbObjectDelete,
			session2.VerbObjectRange,
			session2.VerbObjectRangeHash,
		}
	)

	for _, c := range ctxs {
		var v2Verb session2.Verb

		switch c.verb {
		case session.VerbContainerPut:
			v2Verb = session2.VerbContainerPut
		case session.VerbContainerDelete:
			v2Verb = session2.VerbContainerDelete
		case session.VerbContainerSetEACL:
			v2Verb = session2.VerbContainerSetEACL
		case session.VerbContainerSetAttribute:
			v2Verb = session2.VerbContainerSetAttribute
		case session.VerbContainerRemoveAttribute:
			v2Verb = session2.VerbContainerRemoveAttribute
		default:
			return nil, fmt.Errorf("unknown verb: %v", c.verb)
		}

		if _, ok := verbsByCnr[c.containerID]; !ok {
			verbsByCnr[c.containerID] = []session2.Verb{v2Verb}
			continue
		}

		verbsByCnr[c.containerID] = append(verbsByCnr[c.containerID], append(objectOperations, v2Verb)...)
	}

	deduplicate, err := deduplicateVerbs(verbsByCnr)
	if err != nil {
		return nil, fmt.Errorf("deduplicate verbs: %w", err)
	}

	slices.SortFunc(deduplicate, func(a, b session2.Context) int {
		return a.Container().Compare(b.Container())
	})

	sessionTokens, err := buildSessionTokenV2(key, lifetime, deduplicate, gatesKeys)
	if err != nil {
		return nil, fmt.Errorf("build session tokens v2: %w", err)
	}

	return sessionTokens, nil
}

func deduplicateVerbs(m map[cid.ID][]session2.Verb) ([]session2.Context, error) {
	var r []session2.Context

	for cnrID, verbs := range m {
		var uniqueVerbsMap = make(map[session2.Verb]struct{}, len(verbs))
		for _, verb := range verbs {
			uniqueVerbsMap[verb] = struct{}{}
		}

		uniqueVerbs := maps.Keys(uniqueVerbsMap)
		sortedVerbs := slices.Sorted(uniqueVerbs)

		newContext, err := session2.NewContext(cnrID, sortedVerbs)
		if err != nil {
			return nil, fmt.Errorf("session context: %w", err)
		}

		r = append(r, newContext)
	}

	return r, nil
}

func createTokens(options *IssueSecretOptions, lifetime lifetimeOptions) ([]*accessbox.GateData, error) {
	var gates []*accessbox.GateData

	if !options.SkipSessionRules {
		sessionRules, err := buildContext(options.SessionTokenRules)
		if err != nil {
			return nil, fmt.Errorf("failed to build context for session token: %w", err)
		}

		sessionTokensV2, err := buildSessionTokensV2(options.NeoFSKey, lifetime, sessionRules, options.GatesPublicKeys)
		if err != nil {
			return nil, fmt.Errorf("failed to build session token v2: %w", err)
		}
		for _, sessionTokenV2 := range sessionTokensV2 {
			var gate = accessbox.GateData{
				SessionTokenV2: &sessionTokenV2,
			}

			gates = append(gates, &gate)
		}
	}

	return gates, nil
}
