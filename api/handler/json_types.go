package handler

import (
	"encoding/json"
	"slices"
)

type (
	stringOrSlice struct {
		values []string
	}
)

func (s *stringOrSlice) UnmarshalJSON(bytes []byte) error {
	if err := json.Unmarshal(bytes, &s.values); err == nil {
		return nil
	}

	var str string
	if err := json.Unmarshal(bytes, &str); err != nil {
		return err
	}

	s.values = []string{str}
	return nil
}

func (s stringOrSlice) MarshalJSON() ([]byte, error) {
	values := s.values
	if values == nil {
		values = []string{}
	}

	if len(s.values) == 1 {
		str := s.values[0]
		return json.Marshal(&str)
	}

	return json.Marshal(values)
}

func (s stringOrSlice) Equal(v stringOrSlice) bool {
	if len(s.values) != len(v.values) {
		return false
	}

	slices.Sort(s.values)
	slices.Sort(v.values)

	return slices.Compare(s.values, v.values) == 0
}
