package layer

import (
	"testing"

	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
)

func TestExtractFilePath(t *testing.T) {
	for _, filePath := range []string{"asdf", "_obj1_", "boo/bar", ""} {
		t.Run(filePath, func(t *testing.T) {
			res, err := extractFilePath(generateContinuationToken(filePath))
			require.NoError(t, err)
			require.Equal(t, filePath, res)

			res, err = extractFilePath(generateAdjustedContinuationToken(filePath, oidtest.ID()))
			require.NoError(t, err)
			require.Equal(t, filePath, res)
		})
	}

	_, err := extractFilePath("")
	require.Error(t, err)
}
