package authmate

import (
	"encoding/json"
	"fmt"

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

func (c *sessionTokenContext) UnmarshalJSON(data []byte) (err error) {
	var m sessionTokenModel

	if err = json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("unmarshal session token context: %w", err)
	}

	switch m.Verb {
	case containerSessionVerbPut, session.VerbContainerPut.String():
		c.verb = session.VerbContainerPut
	case containerSessionVerbSetEACL, session.VerbContainerSetEACL.String():
		c.verb = session.VerbContainerSetEACL
	case containerSessionVerbDelete, session.VerbContainerDelete.String():
		c.verb = session.VerbContainerDelete
	case session.VerbContainerSetAttribute.String():
		c.verb = session.VerbContainerSetAttribute
	case session.VerbContainerRemoveAttribute.String():
		c.verb = session.VerbContainerRemoveAttribute
	case session.VerbObjectPut.String():
		c.verb = session.VerbObjectPut
	case session.VerbObjectGet.String():
		c.verb = session.VerbObjectGet
	case session.VerbObjectHead.String():
		c.verb = session.VerbObjectHead
	case session.VerbObjectSearch.String():
		c.verb = session.VerbObjectSearch
	case session.VerbObjectDelete.String():
		c.verb = session.VerbObjectDelete
	case session.VerbObjectRange.String():
		c.verb = session.VerbObjectRange
	default:
		return fmt.Errorf("unknown session token verb %s", m.Verb)
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

	return []sessionTokenContext{
		{verb: session.VerbContainerPut},
		{verb: session.VerbContainerDelete},
		{verb: session.VerbContainerSetEACL},
		{verb: session.VerbContainerSetAttribute},
		{verb: session.VerbContainerRemoveAttribute},
		{verb: session.VerbObjectPut},
		{verb: session.VerbObjectGet},
		{verb: session.VerbObjectHead},
		{verb: session.VerbObjectSearch},
		{verb: session.VerbObjectDelete},
		{verb: session.VerbObjectRange},
	}, nil
}
