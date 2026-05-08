package accessbox

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	session2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"google.golang.org/protobuf/proto"
)

const (
	accessBoxVersionSessionV2 = 1

	encyptedAccessKeyLength = 76
)

// Box represents friendly AccessBox.
type Box struct {
	Gate     *GateData
	Policies []*ContainerPolicy
}

// ContainerPolicy represents friendly AccessBox_ContainerPolicy.
type ContainerPolicy struct {
	LocationConstraint string
	Policy             netmap.PlacementPolicy
}

// GateData represents gate tokens in AccessBox.
type GateData struct {
	AccessKey      string
	SessionTokenV2 *session2.Token
}

var errDecodeFailed = errors.New("failed to decode accessbox")

// Secrets represents AccessKey and the key to encrypt gate tokens.
type Secrets struct {
	AccessKey    string
	EphemeralKey *keys.PrivateKey
}

// Marshal returns the wire-format of AccessBox.
func (x *AccessBox) Marshal() ([]byte, error) {
	return proto.Marshal(x)
}

// Unmarshal parses the wire-format message and put data to x.
func (x *AccessBox) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, x)
}

// PackTokens adds session tokens to AccessBox.
func PackTokens(gatesData []*GateData, ephemeralKey *keys.PrivateKey, secret []byte) (*AccessBox, *Secrets, error) {
	box := &AccessBox{}
	box.OwnerPublicKey = ephemeralKey.PublicKey().Bytes()
	box.Version = accessBoxVersionSessionV2

	if err := box.addTokens(gatesData); err != nil {
		return nil, nil, fmt.Errorf("failed to add tokens to accessbox: %w", err)
	}

	return box, &Secrets{hex.EncodeToString(secret), ephemeralKey}, nil
}

// GetTokens returns gate tokens from AccessBox.
func (x *AccessBox) GetTokens(owner *keys.PrivateKey, resolver session2.NNSResolver) (*GateData, error) {
	if x.Version != accessBoxVersionSessionV2 {
		return nil, fmt.Errorf("unsupported access box version %d (current: %d)", x.Version, accessBoxVersionSessionV2)
	}

	sender, err := keys.NewPublicKeyFromBytes(x.OwnerPublicKey, elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal OwnerPublicKey: %w", err)
	}
	ownerID := user.NewFromScriptHash(owner.PublicKey().GetScriptHash())

	for _, gate := range x.Gates {
		gateData, err := decodeGateV2(gate, owner, sender)
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
func (x *AccessBox) GetBox(owner *keys.PrivateKey, resolver session2.NNSResolver) (*Box, error) {
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

func decodeGateV2(gate *AccessBox_Gate, owner *keys.PrivateKey, sender *keys.PublicKey) (*GateData, error) {
	var tokens TokensV2
	if err := proto.Unmarshal(gate.Tokens, &tokens); err != nil {
		return nil, fmt.Errorf("unmarshal tokens: %w", err)
	}

	var (
		stv2       session2.Token
		gateUserID = user.NewFromScriptHash(owner.GetScriptHash())
		index      = -1
	)

	if err := stv2.Unmarshal(tokens.SessionTokenV2); err != nil {
		return nil, fmt.Errorf("unmarshal session token v2: %w", err)
	}

	var appData = stv2.AppData()
	if len(appData) == 0 {
		return nil, errors.New("empty app data")
	}

	for i, target := range stv2.Subjects() {
		if target.UserID() == gateUserID {
			index = i
			break
		}
	}

	if index == -1 {
		return nil, errDecodeFailed
	}

	startIndex := encyptedAccessKeyLength * index
	if startIndex+encyptedAccessKeyLength > len(appData) {
		return nil, errors.New("gate component not found in token app data")
	}

	enc := appData[startIndex : startIndex+encyptedAccessKeyLength]

	accessKey, err := accessbox.Decrypt(owner, sender, enc)
	if err == nil {
		gateData := GateData{
			AccessKey:      hex.EncodeToString(accessKey),
			SessionTokenV2: &stv2,
		}
		return &gateData, nil
	}

	return nil, err
}
