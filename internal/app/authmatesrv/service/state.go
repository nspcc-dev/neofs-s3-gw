package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type (
	// issuanceState carries what the complete call needs from the prepare one. It is
	// handed to the client as is, so it must not hold anything the client may not see.
	issuanceState struct {
		EphemeralKey []byte `json:"key"`
	}
)

func (s issuanceState) encode() (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("encode: %w", err)
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func decodeState(state string) (issuanceState, error) {
	var result issuanceState

	data, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return result, fmt.Errorf("malformed base64 encoding: %w", err)
	}

	if err = json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("decode: %w", err)
	}

	return result, nil
}
