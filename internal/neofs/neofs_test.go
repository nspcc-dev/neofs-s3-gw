package neofs

import (
	"fmt"
	"testing"

	"github.com/nspcc-dev/neofs-s3-gw/api/handler"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/stretchr/testify/require"
)

func TestErrorChecking(t *testing.T) {
	reason := "some reason"
	err := new(apistatus.ObjectAccessDenied)
	err.WriteReason(reason)

	var wrappedError error

	if fetchedReason, ok := isErrAccessDenied(err); ok {
		wrappedError = fmt.Errorf("%w: %s", handler.ErrAccessDenied, fetchedReason)
	}

	require.ErrorIs(t, wrappedError, handler.ErrAccessDenied)
	require.Contains(t, wrappedError.Error(), reason)
}
