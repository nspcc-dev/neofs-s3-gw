package main

import (
	"crypto/ecdsa"
	"time"

	"github.com/nspcc-dev/neofs-authmate/accessbox/hcs"
	"github.com/nspcc-dev/neofs-s3-gate/api/pool"
	"go.uber.org/zap"
)

type (
	authCenterParams struct {
		Pool    pool.Client
		Logger  *zap.Logger
		Timeout time.Duration

		GateAuthKeys    *hcs.X25519Keys
		NeoFSPrivateKey *ecdsa.PrivateKey
	}
)
