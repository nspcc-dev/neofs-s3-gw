package notifications

import (
	"time"

	"github.com/nats-io/nats.go"
)

const (
	DefaultTimeout = 30 * time.Second
)

type Options struct {
	URL                       string
	TLSCertFilepath           string
	TLSAuthPrivateKeyFilePath string
	Timeout                   time.Duration
	RootCAFiles               []string
}

type Controller struct {
	taskQueueConnection *nats.Conn
	jsClient            nats.JetStream
}

func NewController(p *Options) (*Controller, error) {
	if p == nil {
		return nil, nil
	}

	ncopts := []nats.Option{
		nats.ClientCert(p.TLSCertFilepath, p.TLSAuthPrivateKeyFilePath),
		nats.RootCAs(p.RootCAFiles...),
		nats.Timeout(p.Timeout),
	}

	nc, err := nats.Connect(p.URL, ncopts...)
	if err != nil {
		return nil, err
	}

	js, err := nc.JetStream()
	if err != nil {
		return nil, err
	}

	return &Controller{
		taskQueueConnection: nc,
		jsClient:            js,
	}, nil
}
