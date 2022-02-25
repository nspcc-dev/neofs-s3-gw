package notifications

import (
	"context"
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

	go c.Listen(p.SubscribeSubjectName)

	return c, nil
}

func (c *Controller) Listen(subject string) {
	sub, err := c.jsClient.PullSubscribe(subject, "default")
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			msgs, _ := sub.Fetch(1, nats.Context(ctx))
			for _, msg := range msgs {
				_ = msg.Ack()
			}
		}
	}
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
