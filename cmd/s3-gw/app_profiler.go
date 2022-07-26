package main

import (
	"net/http"
	"net/http/pprof"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// NewPprofService creates a new service for gathering pprof metrics.
func NewPprofService(v *viper.Viper, l *zap.Logger) *Service {
	handler := http.NewServeMux()
	handler.HandleFunc("/debug/pprof/", pprof.Index)
	handler.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	handler.HandleFunc("/debug/pprof/profile", pprof.Profile)
	handler.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	handler.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Manually add support for paths linked to by index page at /debug/pprof/
	for _, item := range []string{"allocs", "block", "heap", "goroutine", "mutex", "threadcreate"} {
		handler.Handle("/debug/pprof/"+item, pprof.Handler(item))
	}

	return &Service{
		Server: &http.Server{
			Addr:    v.GetString(cfgPProfAddress),
			Handler: handler,
		},
		enabled:     v.GetBool(cfgPProfEnabled),
		serviceType: "Pprof",
		log:         l.With(zap.String("service", "Pprof")),
	}
}
