package tokens

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-s3-gw/api/cache"
	"github.com/nspcc-dev/neofs-s3-gw/creds/accessbox"
	internalbox "github.com/nspcc-dev/neofs-s3-gw/internal/accessbox"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type neoFSStub struct {
	NeoFS
	payload []byte
	err     error
}

func (s *neoFSStub) ReadObject(context.Context, oid.Address) ([]byte, *object.Object, error) {
	if s.err != nil {
		return nil, nil, s.err
	}
	return s.payload, new(object.Object), nil
}

type resolverStub struct {
	err error
}

func (s resolverStub) HasUser(string, user.ID) (bool, error) {
	return false, s.err
}

// newBox returns a marshaled access box issued for the gate key. The gate is
// the last token subject, after the given ones.
func newBox(t *testing.T, gateKey *keys.PrivateKey, subjects ...session.Target) []byte {
	issuerKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	issuer := user.NewAutoIDSignerRFC6979(issuerKey.PrivateKey)

	enc, err := internalbox.EncryptV2(gateKey.PublicKey(), make([]byte, 32))
	require.NoError(t, err)

	appData := make([]byte, len(subjects)*len(enc))
	appData = append(appData, enc...)

	var tok session.Token
	tok.SetVersion(session.TokenCurrentVersion)
	tok.SetIssuer(issuer.UserID())
	require.NoError(t, tok.SetSubjects(append(subjects, session.NewTargetUser(user.NewFromScriptHash(gateKey.GetScriptHash())))))
	require.NoError(t, tok.SetAppData(appData))
	require.NoError(t, tok.Sign(issuer))

	box, err := accessbox.PackTokens([]*accessbox.GateData{{SessionTokenV2: &tok}})
	require.NoError(t, err)

	data, err := box.Marshal()
	require.NoError(t, err)

	return data
}

func TestGetBoxErrors(t *testing.T) {
	gateKey, err := keys.NewPrivateKey()
	require.NoError(t, err)
	otherKey, err := keys.NewPrivateKey()
	require.NoError(t, err)

	// What a storage node answers when it has lost the FS chain.
	var nodeFailure apistatus.BadRequest
	nodeFailure.SetMessage("connection to the RPC node has been lost")

	t.Run("valid", func(t *testing.T) {
		c := New(&neoFSStub{payload: newBox(t, gateKey)}, gateKey, cache.DefaultAccessBoxConfig(zap.NewNop()), nil)
		_, err := c.GetBox(context.Background(), oidtest.Address())
		require.NoError(t, err)
	})

	for _, tc := range []struct {
		name     string
		neoFS    neoFSStub
		resolver session.NNSResolver
		invalid  bool
	}{
		{name: "object not found", neoFS: neoFSStub{err: fmt.Errorf("read: %w", apistatus.ErrObjectNotFound)}, invalid: true},
		{name: "object removed", neoFS: neoFSStub{err: fmt.Errorf("read: %w", apistatus.ErrObjectAlreadyRemoved)}, invalid: true},
		{name: "container not found", neoFS: neoFSStub{err: fmt.Errorf("read: %w", apistatus.ErrContainerNotFound)}, invalid: true},
		{name: "empty object", neoFS: neoFSStub{err: fmt.Errorf("read: %w", apistatus.ErrObjectOutOfRange)}, invalid: true},
		{name: "marked by NeoFS", neoFS: neoFSStub{err: fmt.Errorf("%w: access denied", ErrInvalidAccessBox)}, invalid: true},
		{name: "not a box", neoFS: neoFSStub{payload: []byte("not a box")}, invalid: true},
		{name: "unsupported version", neoFS: neoFSStub{payload: []byte{}}, invalid: true},
		{name: "other gate", neoFS: neoFSStub{payload: newBox(t, otherKey)}, invalid: true},
		{name: "node failure", neoFS: neoFSStub{err: fmt.Errorf("read: %w", nodeFailure)}},
		{name: "connection failure", neoFS: neoFSStub{err: errors.New("connection refused")}},
		{
			name:     "resolver failure",
			neoFS:    neoFSStub{payload: newBox(t, gateKey, session.NewTargetNamed("gates.neofs"))},
			resolver: resolverStub{err: errors.New("resolver failure")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(&tc.neoFS, gateKey, cache.DefaultAccessBoxConfig(zap.NewNop()), tc.resolver)

			_, err := c.GetBox(context.Background(), oidtest.Address())
			require.Error(t, err)
			require.Equal(t, tc.invalid, errors.Is(err, ErrInvalidAccessBox), err)
		})
	}
}
