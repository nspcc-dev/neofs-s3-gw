package layer

import (
	"errors"
	"fmt"
	"testing"

	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/stretchr/testify/require"
)

func TestIsErrObjectGone(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		gone bool
	}{
		{name: "already removed", err: apistatus.ObjectAlreadyRemoved{}, gone: true},
		{name: "already removed pointer", err: new(apistatus.ObjectAlreadyRemoved), gone: true},
		{name: "already removed wrapped", err: fmt.Errorf("read header: %w", apistatus.ErrObjectAlreadyRemoved), gone: true},
		{name: "not found", err: apistatus.ErrObjectNotFound, gone: true},
		{name: "not found wrapped", err: fmt.Errorf("read header: %w", apistatus.ErrObjectNotFound), gone: true},
		{name: "access denied", err: apistatus.ErrObjectAccessDenied, gone: false},
		{name: "other", err: errors.New("connection refused"), gone: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.gone, IsErrObjectGone(tc.err))
		})
	}
}
