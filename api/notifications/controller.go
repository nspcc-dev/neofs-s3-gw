package notifications

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nspcc-dev/neofs-s3-gw/api/layer"
	"go.uber.org/zap"
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
	logger              *zap.Logger
	taskQueueConnection *nats.Conn
	jsClient            nats.JetStreamContext
	handlers            map[string]Stream
	mu                  sync.RWMutex
}

type Stream struct {
	h  layer.MsgHandler
	ch chan *nats.Msg
}

func NewController(p *Options, l *zap.Logger) (*Controller, error) {
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

	return &Controller{
		logger:              l,
		taskQueueConnection: nc,
		jsClient:            js,
		handlers:            make(map[string]Stream),
	}, nil
}

func (c *Controller) Subscribe(ctx context.Context, topic string, handler layer.MsgHandler) error {
	ch := make(chan *nats.Msg, 1)

	c.mu.RLock()
	if _, ok := c.handlers[topic]; ok {
		return fmt.Errorf("already subscribed to topic '%s'", topic)
	}
	c.mu.RUnlock()

	if _, err := c.jsClient.AddStream(&nats.StreamConfig{Name: topic}); err != nil {
		return err
	}

	if _, err := c.jsClient.ChanSubscribe(topic, ch); err != nil {
		return fmt.Errorf("could not subscribe: %w", err)
	}

	c.mu.Lock()
	c.handlers[topic] = Stream{
		h:  handler,
		ch: ch,
	}
	c.mu.Unlock()

	return nil
}

func (c *Controller) Listen(ctx context.Context) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, stream := range c.handlers {
		go func(stream Stream) {
			for {
				select {
				case msg := <-stream.ch:
					if err := stream.h.HandleMessage(ctx, msg); err != nil {
						c.logger.Error("could not handle message", zap.Error(err))
					} else if err = msg.Ack(); err != nil {
						c.logger.Error("could not ACK message", zap.Error(err))
					}
				case <-ctx.Done():
					return
				}
			}
		}(stream)
	}
}
