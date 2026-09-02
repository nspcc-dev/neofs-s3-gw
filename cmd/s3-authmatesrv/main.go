package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/nspcc-dev/neofs-s3-gw/internal/app/authmatesrv"
)

func main() {
	g, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	v := authmatesrv.NewSettings()
	l := authmatesrv.NewLogger(v)
	a := authmatesrv.NewApp(l, v)

	a.Serve(g)
}
