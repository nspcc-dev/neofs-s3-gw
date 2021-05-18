package s3

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"time"

	sdk "github.com/nspcc-dev/cdn-sdk"
	"github.com/nspcc-dev/cdn-sdk/creds/bearer"
	"github.com/nspcc-dev/cdn-sdk/creds/hcs"
	"github.com/nspcc-dev/cdn-sdk/creds/neofs"
	"github.com/nspcc-dev/cdn-sdk/creds/s3"
	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/netmap"
	"github.com/nspcc-dev/neofs-api-go/pkg/object"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-node/pkg/policy"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const defaultAuthContainerBasicACL uint32 = 0b00111100100011001000110011001100

type Agent struct {
	cli sdk.Client
	log *zap.Logger
}

func New(log *zap.Logger, client sdk.Client) *Agent {
	return &Agent{log: log, cli: client}
}

type (
	IssueSecretOptions struct {
		ContainerID           *container.ID
		ContainerFriendlyName string
		NEOFSCreds            neofs.Credentials
		OwnerPrivateKey       hcs.PrivateKey
		GatesPublicKeys       []hcs.PublicKey
		EACLRules             []byte
	}

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

func (a *Agent) checkContainer(ctx context.Context, cid *container.ID, friendlyName string) (*container.ID, error) {
	if cid != nil {
		// check that container exists
		_, err := a.cli.Container().Get(ctx, cid)
		return cid, err
	}

	pp, err := buildPlacementPolicy("")
	if err != nil {
		return nil, errors.Wrap(err, "failed to build placement policy")
	}

	cnr := container.New(
		container.WithPolicy(pp),
		container.WithCustomBasicACL(defaultAuthContainerBasicACL),
		container.WithAttribute(container.AttributeName, friendlyName),
		container.WithAttribute(container.AttributeTimestamp, strconv.FormatInt(time.Now().Unix(), 10)))

	return a.cli.Container().Put(ctx, cnr,
		sdk.ContainerPutAndWait(),
		sdk.ContainerPutWithTimeout(120*time.Second))
}

func (a *Agent) IssueSecret(ctx context.Context, w io.Writer, options *IssueSecretOptions) error {
	var (
		err error
		cid *container.ID
	)

	a.log.Info("check container", zap.Stringer("cid", options.ContainerID))
	if cid, err = a.checkContainer(ctx, options.ContainerID, options.ContainerFriendlyName); err != nil {
		return err
	}

	a.log.Info("prepare eACL table")

	table, err := buildEACLTable(cid, options.EACLRules)
	if err != nil {
		return errors.Wrap(err, "failed to build eacl table")
	}

	tkn, err := buildBearerToken(options.NEOFSCreds.PrivateKey(), options.NEOFSCreds.Owner(), table)
	if err != nil {
		return errors.Wrap(err, "failed to build bearer token")
	}

	a.log.Info("store bearer token into NeoFS",
		zap.Stringer("owner_key", options.NEOFSCreds.Owner()),
		zap.Stringer("owner_tkn", tkn.Issuer()))

	address, err := bearer.
		New(a.cli.Object(), options.OwnerPrivateKey).
		Put(ctx, cid, tkn, options.GatesPublicKeys...)
	if err != nil {
		return errors.Wrap(err, "failed to put bearer token")
	}

	secret, err := s3.SecretAccessKey(tkn)
	if err != nil {
		return errors.Wrap(err, "failed to get bearer token secret key")
	}

	ir := &issuingResult{
		AccessKeyID:     address.String(),
		SecretAccessKey: secret,
		OwnerPrivateKey: options.OwnerPrivateKey.String(),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ir)
}

func (a *Agent) ObtainSecret(ctx context.Context, w io.Writer, options *ObtainSecretOptions) error {
	bearerCreds := bearer.New(a.cli.Object(), options.GatePrivateKey)
	address := object.NewAddress()
	if err := address.Parse(options.SecretAddress); err != nil {
		return errors.Wrap(err, "failed to parse secret address")
	}

	tkn, err := bearerCreds.Get(ctx, address)
	if err != nil {
		return errors.Wrap(err, "failed to get bearer token")
	}

	secret, err := s3.SecretAccessKey(tkn)
	if err != nil {
		return errors.Wrap(err, "failed to get bearer token secret key")
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

// selects <count> nodes in container without any additional attributes
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

func buildEACLTable(cid *container.ID, eaclTable []byte) (*eacl.Table, error) {
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

func buildBearerToken(key *ecdsa.PrivateKey, oid *owner.ID, table *eacl.Table) (*token.BearerToken, error) {
	bearerToken := token.NewBearerToken()
	bearerToken.SetEACLTable(table)
	bearerToken.SetOwner(oid)
	bearerToken.SetLifetime(math.MaxUint64, 0, 0)

	return bearerToken, bearerToken.SignToken(key)
}
