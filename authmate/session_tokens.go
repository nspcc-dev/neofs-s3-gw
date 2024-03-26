package authmate

import (
	"encoding/json"
	"fmt"

	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

type (
	sessionTokenModel struct {
		Verb        string `json:"verb"`
		ContainerID string `json:"containerID"`
	}

	sessionTokenContext struct {
		verb        session.ContainerVerb
		containerID cid.ID
	}
)

// JSON strings for supported container session verbs.
const (
	containerSessionVerbPut     = "PUT"
	containerSessionVerbDelete  = "DELETE"
	containerSessionVerbSetEACL = "SETEACL"
)

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
		return fmt.Errorf("unknown container token verb %s", m.Verb)
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
			if d.verb == session.VerbContainerPut {
				containsPut = true
			} else if d.verb == session.VerbContainerSetEACL {
				containsSetEACL = true
			}
		}
		if containsPut && !containsSetEACL {
			sessionCtxs = append(sessionCtxs, sessionTokenContext{
				verb: session.VerbContainerSetEACL,
			})
		}

		return sessionCtxs, nil
	}

	return []sessionTokenContext{
		{verb: session.VerbContainerPut},
		{verb: session.VerbContainerDelete},
		{verb: session.VerbContainerSetEACL},
	}, nil
}
