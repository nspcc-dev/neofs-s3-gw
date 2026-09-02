package authmate

import (
	"testing"

	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
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
  },
  {
    "verb": "DELETE",
    "ContainerID": "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1"
  },
  {
    "verb": "CONTAINER_SET_ATTRIBUTE"
  },
  {
    "verb": "CONTAINER_REMOVE_ATTRIBUTE"
  },
  {
    "verb": "OBJECT_PUT"
  },
  {
    "verb": "OBJECT_GET"
  },
  {
    "verb": "OBJECT_HEAD"
  },
  {
    "verb": "OBJECT_SEARCH"
  },
  {
    "verb": "OBJECT_DELETE",
    "containerID": "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1"
  },
  {
    "verb": "OBJECT_RANGE"
  }
]`)

	sessionContext, err := buildContext(jsonRules)
	require.NoError(t, err)

	require.Len(t, sessionContext, 12)
	require.Equal(t, sessionContext[0].verb, session.VerbContainerPut)
	require.Zero(t, sessionContext[0].containerID)
	require.Equal(t, sessionContext[1].verb, session.VerbContainerDelete)
	require.NotNil(t, sessionContext[1].containerID)
	require.Equal(t, sessionContext[2].verb, session.VerbContainerSetEACL)
	require.Zero(t, sessionContext[2].containerID)
	require.Equal(t, sessionContext[1], sessionContext[3])
	require.Equal(t, session.VerbContainerSetAttribute, sessionContext[4].verb)
	require.Zero(t, sessionContext[4].containerID)
	require.Equal(t, session.VerbContainerRemoveAttribute, sessionContext[5].verb)
	require.Zero(t, sessionContext[5].containerID)

	require.Equal(t, session.VerbObjectPut, sessionContext[6].verb)
	require.Zero(t, sessionContext[6].containerID)
	require.Equal(t, session.VerbObjectGet, sessionContext[7].verb)
	require.Zero(t, sessionContext[7].containerID)
	require.Equal(t, session.VerbObjectHead, sessionContext[8].verb)
	require.Zero(t, sessionContext[8].containerID)
	require.Equal(t, session.VerbObjectSearch, sessionContext[9].verb)
	require.Zero(t, sessionContext[9].containerID)
	require.Equal(t, session.VerbObjectDelete, sessionContext[10].verb)
	require.NotZero(t, sessionContext[10].containerID)
	require.Equal(t, session.VerbObjectRange, sessionContext[11].verb)
	require.Zero(t, sessionContext[11].containerID)
}

func TestContainerSessionRulesCanonicalVerbs(t *testing.T) {
	jsonRules := []byte(`
[
  {
    "verb": "CONTAINER_PUT"
  },
  {
    "verb": "CONTAINER_DELETE"
  },
  {
    "verb": "CONTAINER_SET_EACL"
  }
]`)

	sessionContext, err := buildContext(jsonRules)
	require.NoError(t, err)

	require.Len(t, sessionContext, 3)
	require.Equal(t, session.VerbContainerPut, sessionContext[0].verb)
	require.Equal(t, session.VerbContainerDelete, sessionContext[1].verb)
	require.Equal(t, session.VerbContainerSetEACL, sessionContext[2].verb)
}

func TestContainerSessionRulesUnknownVerb(t *testing.T) {
	jsonRules := []byte(`
[
  {
    "verb": "UNKNOWN",
    "containerID": null
  }
]`)

	_, err := buildContext(jsonRules)
	require.Error(t, err)
}

func TestBuildContexts(t *testing.T) {
	t.Run("default rules", func(t *testing.T) {
		contexts, err := BuildContexts(nil)
		require.NoError(t, err)

		// Every default verb applies to every container, so they all collapse
		// into a single wildcard context.
		require.Len(t, contexts, 1)
		require.True(t, contexts[0].Container().IsZero())
		require.Len(t, contexts[0].Verbs(), 11)
	})

	t.Run("sorted and deduplicated", func(t *testing.T) {
		contexts, err := BuildContexts([]byte(`
[
  {"verb": "OBJECT_GET"},
  {"verb": "OBJECT_GET"},
  {"verb": "OBJECT_PUT", "containerID": "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1"}
]`))
		require.NoError(t, err)

		require.Len(t, contexts, 2)
		require.True(t, contexts[0].Container().IsZero())
		require.Equal(t, []session.Verb{session.VerbObjectGet}, contexts[0].Verbs())
		require.False(t, contexts[1].Container().IsZero())
		require.Equal(t, []session.Verb{session.VerbObjectPut}, contexts[1].Verbs())
	})

	t.Run("empty rules", func(t *testing.T) {
		_, err := BuildContexts([]byte(`[]`))
		require.ErrorContains(t, err, "no session token rules")
	})

	t.Run("explicit container repeating the wildcard", func(t *testing.T) {
		_, err := BuildContexts([]byte(`
[
  {"verb": "OBJECT_GET"},
  {"verb": "OBJECT_GET", "containerID": "6CcWg8LkcbfMUC8pt7wiy5zM1fyS3psNoxgfppcCgig1"}
]`))
		require.ErrorContains(t, err, "same verbs as the wildcard context")
	})

	t.Run("unknown verb", func(t *testing.T) {
		_, err := BuildContexts([]byte(`[{"verb": "UNKNOWN"}]`))
		require.Error(t, err)
	})
}

func TestParseVerb(t *testing.T) {
	for _, verb := range supportedVerbs {
		parsed, err := ParseVerb(verb.String())
		require.NoError(t, err)
		require.Equal(t, verb, parsed)
	}

	_, err := ParseVerb(session.VerbUnspecified.String())
	require.Error(t, err)
}
