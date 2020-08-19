package handler

import (
	"errors"

	"github.com/nspcc-dev/neofs-s3-gate/api"
	"github.com/nspcc-dev/neofs-s3-gate/api/layer"
	"go.uber.org/zap"
)

type (
	handler struct {
		log *zap.Logger
		obj layer.Client
	}

	Params struct {
		Log *zap.Logger
		Obj layer.Client
	}
)

const notSupported = "Not supported by NeoFS S3 Gate: "

var _ api.Handler = (*handler)(nil)

func New(log *zap.Logger, obj layer.Client) (api.Handler, error) {
	switch {
	case obj == nil:
		return nil, errors.New("empty NeoFS Object Layer")
	case log == nil:
		return nil, errors.New("empty logger")
	}

	return &handler{
		log: log,
		obj: obj,
	}, nil
}
