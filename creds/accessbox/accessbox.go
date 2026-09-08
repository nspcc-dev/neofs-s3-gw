package accessbox

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"google.golang.org/protobuf/proto"
)

const (
	accessBoxVersionSessionV2 = 1
	accessBoxVersionHPKE      = 2

	accessBoxVersionCurrent = accessBoxVersionHPKE
)

// Box represents friendly AccessBox.
type Box struct {
	Gate      *GateData
	Policies  []*ContainerPolicy
	Namespace string
}

// ContainerPolicy represents friendly AccessBox_ContainerPolicy.
type ContainerPolicy struct {
	LocationConstraint string
	Policy             netmap.PlacementPolicy
}

// GateData represents gate tokens in AccessBox.
type GateData struct {
	AccessKey      string
	SessionTokenV2 *session.Token
}

var errDecodeFailed = errors.New("failed to decode accessbox")

// Marshal returns the wire-format of AccessBox.
func (x *AccessBox) Marshal() ([]byte, error) {
	return proto.Marshal(x)
}

// Unmarshal parses the wire-format message and put data to x.
func (x *AccessBox) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, x)
}

// PackTokens adds session tokens to AccessBox.
func PackTokens(gatesData []*GateData) (*AccessBox, error) {
	box := &AccessBox{}
	box.Version = accessBoxVersionCurrent

	if err := box.addTokens(gatesData); err != nil {
		return nil, fmt.Errorf("failed to add tokens to accessbox: %w", err)
	}

	return box, nil
}

// GetTokens returns gate tokens from AccessBox.
func (x *AccessBox) GetTokens(owner *keys.PrivateKey, resolver session.NNSResolver) (*GateData, error) {
	var decodeFunc func(*AccessBox_Gate) (*GateData, error)

	switch x.Version {
	case accessBoxVersionSessionV2:
		// The sender key is a part of the version 1 scheme only, version 2 boxes leave it empty.
		sender, err := keys.NewPublicKeyFromBytes(x.OwnerPublicKey, elliptic.P256())
		if err != nil {
			return nil, fmt.Errorf("couldn't unmarshal OwnerPublicKey: %w", err)
		}

		decodeFunc = func(gate *AccessBox_Gate) (*GateData, error) {
			return decodeGateV1(gate, owner, sender)
		}
	case accessBoxVersionHPKE:
		decodeFunc = func(gate *AccessBox_Gate) (*GateData, error) {
			return decodeGateV2(gate, owner)
		}
	default:
		return nil, fmt.Errorf("unsupported access box version %d (current: %d)", x.Version, accessBoxVersionCurrent)
	}
	ownerID := user.NewFromScriptHash(owner.PublicKey().GetScriptHash())

	for _, gate := range x.Gates {
		gateData, err := decodeFunc(gate)
		if err != nil {
			if errors.Is(err, errDecodeFailed) {
				continue
			}

			return nil, fmt.Errorf("failed to decode gate: %w", err)
		}

		if gateData.SessionTokenV2 == nil {
			return nil, fmt.Errorf("session token v2 is null")
		}

		ok, err := gateData.SessionTokenV2.AssertAuthority(ownerID, resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to check authority: %w", err)
		}

		// this token doesn't belong to this gate.
		if !ok {
			continue
		}

		return gateData, nil
	}

	return nil, fmt.Errorf("no gate data for key %x was found", owner.PublicKey().Bytes())
}

// GetPlacementPolicy returns ContainerPolicy from AccessBox.
func (x *AccessBox) GetPlacementPolicy() ([]*ContainerPolicy, error) {
	var result []*ContainerPolicy
	for _, policy := range x.ContainerPolicy {
		var cnrPolicy ContainerPolicy
		if err := cnrPolicy.Policy.Unmarshal(policy.Policy); err != nil {
			return nil, fmt.Errorf("unmarshal placement policy: %w", err)
		}

		cnrPolicy.LocationConstraint = policy.LocationConstraint

		result = append(result, &cnrPolicy)
	}

	return result, nil
}

// GetBox parses AccessBox to Box.
func (x *AccessBox) GetBox(owner *keys.PrivateKey, resolver session.NNSResolver) (*Box, error) {
	tokens, err := x.GetTokens(owner, resolver)
	if err != nil {
		return nil, fmt.Errorf("get tokens: %w", err)
	}

	policy, err := x.GetPlacementPolicy()
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}

	return &Box{
		Gate:     tokens,
		Policies: policy,
	}, nil
}

func (x *AccessBox) addTokens(gatesData []*GateData) error {
	for _, gate := range gatesData {
		if gate.SessionTokenV2 == nil {
			return errors.New("session token v2 is required")
		}

		msg := &TokensV2{
			SessionTokenV2: gate.SessionTokenV2.Marshal(),
		}

		boxGate, err := encodeGateV2(msg)
		if err != nil {
			return fmt.Errorf("encode gate v2: %w", err)
		}

		x.Gates = append(x.Gates, boxGate)
	}
	return nil
}

func encodeGateV2(tokens proto.Message) (*AccessBox_Gate, error) {
	data, err := proto.Marshal(tokens)
	if err != nil {
		return nil, fmt.Errorf("encode tokens: %w", err)
	}

	gate := &AccessBox_Gate{}
	gate.Tokens = data
	return gate, nil
}

// gatesData parses the gate session token and returns the token itself along
// with the slice of its application data belonging to this gate.
func gatesData(gate *AccessBox_Gate, owner *keys.PrivateKey, componentLen int) (*session.Token, []byte, error) {
	var tokens TokensV2
	if err := proto.Unmarshal(gate.Tokens, &tokens); err != nil {
		return nil, nil, fmt.Errorf("unmarshal tokens: %w", err)
	}

	var (
		stv2       session.Token
		gateUserID = user.NewFromScriptHash(owner.GetScriptHash())
		index      = -1
	)

	if err := stv2.Unmarshal(tokens.SessionTokenV2); err != nil {
		return nil, nil, fmt.Errorf("unmarshal session token v2: %w", err)
	}

	var appData = stv2.AppData()
	if len(appData) == 0 {
		return nil, nil, errors.New("empty app data")
	}

	for i, target := range stv2.Subjects() {
		if target.UserID() == gateUserID {
			index = i
			break
		}
	}

	if index == -1 {
		return nil, nil, errDecodeFailed
	}

	startIndex := componentLen * index
	if startIndex+componentLen > len(appData) {
		return nil, nil, errors.New("gate component not found in token app data")
	}

	return &stv2, appData[startIndex : startIndex+componentLen], nil
}

func decodeGateV1(gate *AccessBox_Gate, owner *keys.PrivateKey, sender *keys.PublicKey) (*GateData, error) {
	stv2, enc, err := gatesData(gate, owner, accessbox.EncryptedSecretLengthV1)
	if err != nil {
		return nil, err
	}

	accessKey, err := accessbox.DecryptV1(owner, sender, enc)
	if err != nil {
		return nil, err
	}

	return &GateData{
		AccessKey:      hex.EncodeToString(accessKey),
		SessionTokenV2: stv2,
	}, nil
}

func decodeGateV2(gate *AccessBox_Gate, owner *keys.PrivateKey) (*GateData, error) {
	stv2, enc, err := gatesData(gate, owner, accessbox.EncryptedSecretLengthV2)
	if err != nil {
		return nil, err
	}

	if n := len(stv2.AppData()); n != len(stv2.Subjects())*accessbox.EncryptedSecretLengthV2 {
		return nil, fmt.Errorf("app data size %d does not match %d subjects", n, len(stv2.Subjects()))
	}

	accessKey, err := accessbox.DecryptV2(owner, enc)
	if err != nil {
		return nil, err
	}

	return &GateData{
		AccessKey:      hex.EncodeToString(accessKey),
		SessionTokenV2: stv2,
	}, nil
}
