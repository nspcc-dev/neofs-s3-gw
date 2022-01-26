package authmate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainerSessionRules(t *testing.T) {
	jsonRules := []byte(`
[
  {
    "verb": "PUT",
    "wildcard": true,
    "containerID": null
  },
  {
    "verb": "DELETE",
    "wildcard": true,
    "containerID": null
  },
  {
    "verb": "SETEACL",
    "wildcard": true,
    "containerID": null
  }
]`)

	sessionContext, err := buildContext(jsonRules)
	require.NoError(t, err)

	require.Len(t, sessionContext, 3)
	require.True(t, sessionContext[0].IsForPut())
	require.Nil(t, sessionContext[0].Container())
	require.True(t, sessionContext[1].IsForDelete())
	require.Nil(t, sessionContext[1].Container())
	require.True(t, sessionContext[2].IsForSetEACL())
	require.Nil(t, sessionContext[2].Container())
}
