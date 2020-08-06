package handler

import (
	"errors"

	"github.com/minio/minio/neofs/api"
	"github.com/minio/minio/neofs/layer"
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
