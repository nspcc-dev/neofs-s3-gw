package neofs

import (
	"fmt"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/stretchr/testify/require"
)

func TestErrorChecking(t *testing.T) {
	reason := "some reason"
	err := new(apistatus.ObjectAccessDenied)
	err.WriteReason(reason)

	var wrappedError error

	if fetchedReason, ok := isErrAccessDenied(err); ok {
		wrappedError = fmt.Errorf("%w: %s", neofs.ErrAccessDenied, fetchedReason)
	}

	require.ErrorIs(t, wrappedError, neofs.ErrAccessDenied)
	require.Contains(t, wrappedError.Error(), reason)
}
