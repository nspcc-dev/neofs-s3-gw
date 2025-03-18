package layer

import (
	"errors"
)

// TreeService provide interface to interact with tree service using s3 data models.
type TreeService interface {
}

var (
	// ErrNodeNotFound is returned from Tree service in case of not found error.
	ErrNodeNotFound = errors.New("not found")

	// ErrNodeAccessDenied is returned from Tree service in case of access denied error.
	ErrNodeAccessDenied = errors.New("access denied")

	// ErrNoNodeToRemove is returned from Tree service in case of the lack of node with OID to remove.
	ErrNoNodeToRemove = errors.New("no node to remove")

	// ErrPartListIsEmpty is returned if no parts available for the upload.
	ErrPartListIsEmpty = errors.New("part list is empty")
)
