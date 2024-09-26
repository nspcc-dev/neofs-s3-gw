package models

import (
	"errors"
)

var (
	// ErrNotFound indicates we didn't find something. It should be used to avoid unwilling package dependencies.
	ErrNotFound = errors.New("not found")
)
