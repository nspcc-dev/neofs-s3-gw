package main

import (
	"context"
	"os/signal"
	"syscall"
)

func main() {
	g, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	v := newSettings()
	l := newLogger(v)

	a := newApp(g, l, v)

	go a.Serve(g)

	a.Wait()
}
