package authmate

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/session/v2"
)

type (
	sessionTokenModel struct {
		Verb        string `json:"verb"`
		ContainerID string `json:"containerID"`
	}

	sessionTokenContext struct {
		verb        session.Verb
		containerID cid.ID
	}
)

// JSON strings for supported session verbs.
const (
	containerSessionVerbPut     = "PUT"
	containerSessionVerbDelete  = "DELETE"
	containerSessionVerbSetEACL = "SETEACL"
)

var supportedVerbs = []session.Verb{
	session.VerbContainerPut,
	session.VerbContainerDelete,
	session.VerbContainerSetEACL,
	session.VerbContainerSetAttribute,
	session.VerbContainerRemoveAttribute,
	session.VerbObjectPut,
	session.VerbObjectGet,
	session.VerbObjectHead,
	session.VerbObjectSearch,
	session.VerbObjectDelete,
	session.VerbObjectRange,
}

// ParseVerb parses a supported session verb from its canonical name.
func ParseVerb(name string) (session.Verb, error) {
	for _, verb := range supportedVerbs {
		if verb.String() == name {
			return verb, nil
		}
	}

	return 0, fmt.Errorf("unknown session token verb %s", name)
}

func (c *sessionTokenContext) UnmarshalJSON(data []byte) (err error) {
	var m sessionTokenModel

	if err = json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshal session token context: %w", err)
	}

	switch m.Verb {
	case containerSessionVerbPut:
		c.verb = session.VerbContainerPut
	case containerSessionVerbSetEACL:
		c.verb = session.VerbContainerSetEACL
	case containerSessionVerbDelete:
		c.verb = session.VerbContainerDelete
	default:
		if c.verb, err = ParseVerb(m.Verb); err != nil {
			return err
		}
	}

	if len(m.ContainerID) > 0 {
		return c.containerID.DecodeString(m.ContainerID)
	}

	return nil
}

func buildContext(rules []byte) ([]sessionTokenContext, error) {
	var sessionCtxs []sessionTokenContext

	if len(rules) != 0 {
		err := json.Unmarshal(rules, &sessionCtxs)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules for session token: %w", err)
		}

		var (
			containsPut     = false
			containsSetEACL = false
		)
		for _, d := range sessionCtxs {
			switch d.verb {
			case session.VerbContainerPut:
				containsPut = true
			case session.VerbContainerSetEACL:
				containsSetEACL = true
			default:
			}
		}
		if containsPut && !containsSetEACL {
			sessionCtxs = append(sessionCtxs, sessionTokenContext{
				verb: session.VerbContainerSetEACL,
			})
		}

		return sessionCtxs, nil
	}

	sessionCtxs = make([]sessionTokenContext, 0, len(supportedVerbs))
	for _, verb := range supportedVerbs {
		sessionCtxs = append(sessionCtxs, sessionTokenContext{verb: verb})
	}

	return sessionCtxs, nil
}

// BuildContexts converts session token rules into session v2 contexts.
func BuildContexts(rules []byte) ([]session.Context, error) {
	ruleContexts, err := buildContext(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to build context for session token: %w", err)
	}

	if len(ruleContexts) == 0 {
		return nil, errors.New("no session token rules")
	}

	// The rule format carries one verb per entry, so a container may well
	// repeat: such entries are merged.
	verbsByCnr := make(map[cid.ID][]session.Verb)
	for _, c := range ruleContexts {
		verbsByCnr[c.containerID] = append(verbsByCnr[c.containerID], c.verb)
	}

	return NewContexts(verbsByCnr)
}

// NewContexts groups per-container verbs into session v2 contexts: verbs are
// deduplicated and sorted, containers are sorted.
// The zero container ID is the wildcard one.
func NewContexts(verbsByContainer map[cid.ID][]session.Verb) ([]session.Context, error) {
	contexts := make([]session.Context, 0, len(verbsByContainer))

	for cnrID, verbs := range verbsByContainer {
		uniqueVerbs := make(map[session.Verb]struct{}, len(verbs))
		for _, verb := range verbs {
			uniqueVerbs[verb] = struct{}{}
		}

		newContext, err := session.NewContext(cnrID, slices.Sorted(maps.Keys(uniqueVerbs)))
		if err != nil {
			return nil, fmt.Errorf("session context: %w", err)
		}

		contexts = append(contexts, newContext)
	}

	slices.SortFunc(contexts, func(a, b session.Context) int {
		return a.Container().Compare(b.Container())
	})

	// A token whose explicit container repeats the wildcard verb set exactly is
	// rejected on validation, catch it here where the message can be useful.
	if len(contexts) > 1 && contexts[0].Container().IsZero() {
		wildcardVerbs := contexts[0].Verbs()

		for _, c := range contexts[1:] {
			if slices.Equal(c.Verbs(), wildcardVerbs) {
				return nil, fmt.Errorf("container %s has the same verbs as the wildcard context", c.Container())
			}
		}
	}

	return contexts, nil
}
