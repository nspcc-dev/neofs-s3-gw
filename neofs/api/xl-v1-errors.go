package api

import "errors"

// errXLReadQuorum - did not meet read quorum.
var errXLReadQuorum = errors.New("Read failed. Insufficient number of disks online")

// errXLWriteQuorum - did not meet write quorum.
var errXLWriteQuorum = errors.New("Write failed. Insufficient number of disks online")

// errNoHealRequired - returned when healing is attempted on a previously healed disks.
var errNoHealRequired = errors.New("No healing is required")
