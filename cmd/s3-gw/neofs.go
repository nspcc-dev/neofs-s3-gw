package main

import (
	"context"
	"time"

	layer "github.com/nspcc-dev/neofs-s3-gw/api/layer/neofs"
	"github.com/nspcc-dev/neofs-s3-gw/internal/neofs"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// mediator which implements layer.NeoFS through neofs.NeoFS.
type layerNeoFS struct {
	*neofs.NeoFS
}

func (x *layerNeoFS) CreateContainer(ctx context.Context, prm layer.PrmContainerCreate) (*cid.ID, error) {
	return x.NeoFS.CreateContainer(ctx, neofs.PrmContainerCreate{
		Creator:              prm.Creator,
		Policy:               prm.Policy,
		Name:                 prm.Name,
		Time:                 prm.Time,
		BasicACL:             prm.BasicACL,
		SessionToken:         prm.SessionToken,
		AdditionalAttributes: prm.AdditionalAttributes,
	})
}

func (x *layerNeoFS) CreateObject(ctx context.Context, prm layer.PrmObjectCreate) (*oid.ID, error) {
	return x.NeoFS.CreateObject(ctx, neofs.PrmObjectCreate{
		Creator:     prm.Creator,
		Container:   prm.Container,
		Time:        time.Now().UTC(),
		Filename:    prm.Filename,
		PayloadSize: prm.PayloadSize,
		Attributes:  prm.Attributes,
		Payload:     prm.Payload,
		BearerToken: prm.BearerToken,
		PrivateKey:  prm.PrivateKey,
		Locks:       prm.Locks,
	})
}
