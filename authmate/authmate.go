package authmate

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	cid "github.com/nspcc-dev/neofs-api-go/pkg/container/id"
	"github.com/nspcc-dev/neofs-api-go/pkg/netmap"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-node/pkg/policy"
	"github.com/nspcc-dev/neofs-s3-gw/creds/bearer"
	"github.com/nspcc-dev/neofs-s3-gw/creds/hcs"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/pool"
	"go.uber.org/zap"
)

const (
	defaultAuthContainerBasicACL uint32 = 0b00111100100011001000110011001100
	containerCreationTimeout            = 120 * time.Second
	containerPollInterval               = 5 * time.Second
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
		NeoFSKey              *ecdsa.PrivateKey
		OwnerPrivateKey       hcs.PrivateKey
		GatesPublicKeys       []hcs.PublicKey
		EACLRules             []byte
	}

	// ObtainSecretOptions contains options for passing to Agent.ObtainSecret method.
	ObtainSecretOptions struct {
		SecretAddress  string
		GatePrivateKey hcs.PrivateKey
	}
)

type (
	issuingResult struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		OwnerPrivateKey string `json:"owner_private_key"`
	}

	obtainingResult struct {
		BearerToken     *token.BearerToken `json:"-"`
		SecretAccessKey string             `json:"secret_access_key"`
	}
)

func (a *Agent) checkContainer(ctx context.Context, cid *cid.ID, friendlyName string) (*cid.ID, error) {
	conn, _, err := a.pool.Connection()
	if err != nil {
		return nil, err
	}

	if cid != nil {
		// check that container exists
		_, err = conn.GetContainer(ctx, cid)
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

	cid, err = conn.PutContainer(ctx, cnr)
	if err != nil {
		return nil, err
	}

	wctx, cancel := context.WithTimeout(ctx, containerCreationTimeout)
	defer cancel()
	ticker := time.NewTimer(containerPollInterval)
	defer ticker.Stop()
	wdone := wctx.Done()
	done := ctx.Done()
	for {
		select {
		case <-done:
			return nil, ctx.Err()
		case <-wdone:
			return nil, wctx.Err()
		case <-ticker.C:
			_, err = conn.GetContainer(ctx, cid)
			if err == nil {
				return cid, nil
			}
			ticker.Reset(containerPollInterval)
		}
	}
}

// IssueSecret creates an auth token, puts it in the NeoFS network and writes to io.Writer a new secret access key.
func (a *Agent) IssueSecret(ctx context.Context, w io.Writer, options *IssueSecretOptions) error {
	var (
		err error
		cid *cid.ID
	)

	a.log.Info("check container", zap.Stringer("cid", options.ContainerID))
	if cid, err = a.checkContainer(ctx, options.ContainerID, options.ContainerFriendlyName); err != nil {
		return err
	}

	a.log.Info("prepare eACL table")

	table, err := buildEACLTable(cid, options.EACLRules)
	if err != nil {
		return fmt.Errorf("failed to build eacl table: %w", err)
	}

	tkn, err := buildBearerToken(options.NeoFSKey, table)
	if err != nil {
		return fmt.Errorf("failed to build bearer token: %w", err)
	}

	a.log.Info("store bearer token into NeoFS",
		zap.Stringer("owner_tkn", tkn.Issuer()))

	address, err := bearer.
		New(a.pool, options.OwnerPrivateKey).
		Put(ctx, cid, tkn, options.GatesPublicKeys...)
	if err != nil {
		return fmt.Errorf("failed to put bearer token: %w", err)
	}

	secret, err := BearerToAccessKey(tkn)
	if err != nil {
		return fmt.Errorf("failed to get bearer token secret key: %w", err)
	}

	accessKeyID := address.ContainerID().String() + "_" + address.ObjectID().String()

	ir := &issuingResult{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secret,
		OwnerPrivateKey: options.OwnerPrivateKey.String(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ir)
}

// ObtainSecret receives an existing secret access key from NeoFS and
// writes to io.Writer the secret access key.
func (a *Agent) ObtainSecret(ctx context.Context, w io.Writer, options *ObtainSecretOptions) error {
	bearerCreds := bearer.New(a.pool, options.GatePrivateKey)
	address := object.NewAddress()
	if err := address.Parse(options.SecretAddress); err != nil {
		return fmt.Errorf("failed to parse secret address: %w", err)
	}

	tkn, err := bearerCreds.Get(ctx, address)
	if err != nil {
		return fmt.Errorf("failed to get bearer token: %w", err)
	}

	secret, err := BearerToAccessKey(tkn)
	if err != nil {
		return fmt.Errorf("failed to get bearer token secret key: %w", err)
	}

	or := &obtainingResult{
		BearerToken:     tkn,
		SecretAccessKey: secret,
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

func buildBearerToken(key *ecdsa.PrivateKey, table *eacl.Table) (*token.BearerToken, error) {
	wallet, err := owner.NEO3WalletFromPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	oid := owner.NewIDFromNeo3Wallet(wallet)

	bearerToken := token.NewBearerToken()
	bearerToken.SetEACLTable(table)
	bearerToken.SetOwner(oid)
	bearerToken.SetLifetime(math.MaxUint64, 0, 0)

	return bearerToken, bearerToken.SignToken(key)
}

// BearerToAccessKey returns secret access key generated from given BearerToken.
func BearerToAccessKey(tkn *token.BearerToken) (string, error) {
	data, err := tkn.Marshal()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
