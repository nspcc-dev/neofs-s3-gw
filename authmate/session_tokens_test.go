package authmate

import (
	"testing"

	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/stretchr/testify/require"
)

func TestContainerSessionRules(t *testing.T) {
	jsonRules := []byte(`
[
  {
    "verb": "PUT",
    "containerID": null
  },
  {
    "verb": "DELETE",
    "containerID": "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1"
  },
  {
    "verb": "SETEACL"
  }
]`)

	sessionContext, err := buildContext(jsonRules)
	require.NoError(t, err)

	require.Len(t, sessionContext, 3)
	require.Equal(t, sessionContext[0].verb, session.VerbContainerPut)
	require.Nil(t, sessionContext[0].containerID)
	require.Equal(t, sessionContext[1].verb, session.VerbContainerDelete)
	require.NotNil(t, sessionContext[1].containerID)
	require.Equal(t, sessionContext[2].verb, session.VerbContainerSetEACL)
	require.Nil(t, sessionContext[2].containerID)
}
