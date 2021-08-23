package handler

import (
	"errors"

	"github.com/nspcc-dev/neofs-s3-gw/api"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
)

type (
	handler struct {
		log *zap.Logger
		obj layer.Client
	}
)

var _ api.Handler = (*handler)(nil)

// New creates new api.Handler using given logger and client.
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
