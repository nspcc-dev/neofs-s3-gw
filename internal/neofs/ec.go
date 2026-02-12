package neofs

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	iec "github.com/nspcc-dev/neofs-s3-gw/internal/neofs/ec"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"golang.org/x/sync/errgroup"
)

func (x *NeoFS) ecAndSaveReadyObject(ctx context.Context, signer user.Signer, bTok *bearer.Token, hdr object.Object, pld []byte, rules []netmap.ECRule) error {
	for i := range rules {
		if slices.ContainsFunc(rules[:i], func(rule netmap.ECRule) bool {
			return sameECEncodingRules(rule, rules[i])
		}) {
			// has already been processed, see below
			continue
		}

		payloadParts, err := iec.Encode(rules[i], pld)
		if err != nil {
			return fmt.Errorf("split payload into EC parts for rule #%d (%s): %w", i, iec.RuleStringer(rules[i]), err)
		}

		if err := x.saveECParts(ctx, signer, bTok, hdr, i, payloadParts); err != nil {
			return fmt.Errorf("save EC parts by rule #%d (%s): %w", i, iec.RuleStringer(rules[i]), err)
		}

		for j := i + 1; j < len(rules); j++ {
			if !sameECEncodingRules(rules[i], rules[j]) {
				continue
			}
			if err := x.saveECParts(ctx, signer, bTok, hdr, j, payloadParts); err != nil {
				return fmt.Errorf("save EC parts by rule #%d (%s): %w", j, iec.RuleStringer(rules[j]), err)
			}
		}
	}

	return nil
}

func (x *NeoFS) saveECParts(ctx context.Context, signer user.Signer, bTok *bearer.Token, hdr object.Object, ruleIdx int, parts [][]byte) error {
	eg, egCtx := errgroup.WithContext(ctx)

	for i := range parts {
		partIdx := i

		eg.Go(func() error {
			if err := x.saveECPart(egCtx, signer, bTok, hdr, ruleIdx, parts[partIdx], partIdx); err != nil {
				return fmt.Errorf("save part %d: %w", i, err)
			}

			return nil
		})
	}

	return eg.Wait()
}

func (x *NeoFS) saveECPart(ctx context.Context, signer user.Signer, bTok *bearer.Token, hdr object.Object, ruleIdx int, part []byte, partIdx int) error {
	partObjHdr, err := iec.FormObjectHeaderForECPart(signer, hdr, part, ruleIdx, partIdx)
	if err != nil {
		return fmt.Errorf("form object: %w", err)
	}

	_, err = x.putReadyObject(ctx, signer, bTok, partObjHdr, bytes.NewReader(part), partObjHdr.PayloadSize())
	return err
}

func sameECEncodingRules(a, b netmap.ECRule) bool {
	return a.DataPartNum() == b.DataPartNum() && a.ParityPartNum() == b.ParityPartNum()
}
