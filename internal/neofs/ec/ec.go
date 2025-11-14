package ec

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"github.com/klauspost/reedsolomon"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/tzhash/tz"
)

const (
	attributeRuleIdx = "__NEOFS__EC_RULE_IDX"
	attributePartIdx = "__NEOFS__EC_PART_IDX"
)

// RuleStringer wraps [netmap.ECRule] to provide [fmt.Stringer].
type RuleStringer netmap.ECRule

func (x RuleStringer) String() string {
	n := netmap.ECRule(x)
	return strconv.FormatUint(uint64(n.DataPartNum()), 10) + "/" + strconv.FormatUint(uint64(n.ParityPartNum()), 10)
}

// Encode encodes given data according to specified EC rule and returns coded
// parts. First [netmap.ECRule.DataPartNum] elements are data parts, other
// [netmap.ECRule.ParityPartNum] ones are parity blocks.
//
// All parts are the same length. If data len is not divisible by
// [netmap.ECRule.DataPartNum], last data part is aligned with zeros.
//
// If data is empty, all parts are nil.
func Encode(rule netmap.ECRule, data []byte) ([][]byte, error) {
	dn, pn := rule.DataPartNum(), rule.ParityPartNum()
	if len(data) == 0 {
		return make([][]byte, dn+pn), nil
	}

	enc, err := reedsolomon.New(int(dn), int(pn))
	if err != nil { // should never happen with correct rule
		return nil, fmt.Errorf("init Reed-Solomon decoder: %w", err)
	}

	parts, err := enc.Split(data)
	if err != nil {
		return nil, fmt.Errorf("split data: %w", err)
	}

	if err := enc.Encode(parts); err != nil {
		return nil, fmt.Errorf("calculate Reed-Solomon parity: %w", err)
	}

	return parts, nil
}

// FormObjectHeaderForECPart forms object for EC part produced from given parent object.
func FormObjectHeaderForECPart(signer neofscrypto.Signer, parent object.Object, part []byte, ruleIdx, partIdx int) (object.Object, error) {
	var obj object.Object
	obj.SetVersion(parent.Version())
	obj.SetContainerID(parent.GetContainerID())
	obj.SetOwner(parent.Owner())
	obj.SetCreationEpoch(parent.CreationEpoch())
	obj.SetType(object.TypeRegular)

	obj.SetParent(&parent)
	setIntAttribute(&obj, attributeRuleIdx, ruleIdx)
	setIntAttribute(&obj, attributePartIdx, partIdx)

	obj.SetPayloadSize(uint64(len(part)))
	obj.SetPayloadChecksum(checksum.NewSHA256(sha256.Sum256(part)))
	if _, ok := parent.PayloadHomomorphicHash(); ok {
		obj.SetPayloadHomomorphicHash(checksum.NewTillichZemor(tz.Sum(part)))
	}

	if err := obj.SetIDWithSignature(signer); err != nil {
		return object.Object{}, fmt.Errorf("set verification fields: %w", err)
	}

	return obj, nil
}

func setIntAttribute(dst *object.Object, attr string, val int) {
	setAttribute(dst, attr, strconv.Itoa(val))
}

func setAttribute(dst *object.Object, attr, val string) {
	attrs := dst.Attributes()
	for i := range attrs {
		if attrs[i].Key() == attr {
			attrs[i].SetValue(val)
			dst.SetAttributes(attrs...)
			return
		}
	}

	dst.SetAttributes(append(attrs, object.NewAttribute(attr, val))...)
}
