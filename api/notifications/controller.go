package notifications

import (
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

const (
	DefaultTimeout = 30 * time.Second
)

type (
	Options struct {
		URL                       string
		TLSCertFilepath           string
		TLSAuthPrivateKeyFilePath string
		Timeout                   time.Duration
		RootCAFiles               []string
		SubscribeSubjectName      string
		PublishStreamName         string
		PublishSubjectName        string
	}

	Controller struct {
		taskQueueConnection *nats.Conn
		jsClient            nats.JetStream
		logger              *zap.Logger
	}
)

func NewController(p *Options, l *zap.Logger) (*Controller, error) {
	if p == nil {
		return nil, nil
	}

	ncopts := []nats.Option{
		nats.Timeout(p.Timeout),
	}

	if len(p.TLSCertFilepath) != 0 && len(p.TLSAuthPrivateKeyFilePath) != 0 {
		ncopts = append(ncopts, nats.ClientCert(p.TLSCertFilepath, p.TLSAuthPrivateKeyFilePath))
	}
	if len(p.RootCAFiles) != 0 {
		ncopts = append(ncopts, nats.RootCAs(p.RootCAFiles...))
	}

	nc, err := nats.Connect(p.URL, ncopts...)
	if err != nil {
		return nil, err
	}

	js, err := nc.JetStream()
	if err != nil {
		return nil, err
	}

	if err := createPublishStream(js, p); err != nil {
		return nil, err
	}

	c := &Controller{
		taskQueueConnection: nc,
		jsClient:            js,
		logger:              l,
	}

	return c, nil
}

func createPublishStream(js nats.JetStreamContext, p *Options) error {
	stream, err := js.StreamInfo(p.PublishStreamName)
	if err != nil && !strings.Contains(err.Error(), "stream not found") {
		return err
	}
	if stream == nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     p.PublishStreamName,
			Subjects: []string{p.PublishSubjectName},
		})
		if err != nil {
			return err
		}
	}

	return nil
}
