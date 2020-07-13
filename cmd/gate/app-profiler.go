package main

import (
	"net/http/pprof"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func attachProfiler(r *mux.Router, v *viper.Viper, l *zap.Logger) {
	if !v.GetBool(cfgEnableProfiler) {
		return
	}

	l.Info("enable profiler")

	profiler := r.PathPrefix(systemPath + "/debug/pprof").
		Subrouter().
		StrictSlash(true)

	profiler.HandleFunc("/", pprof.Index)
	profiler.HandleFunc("/cmdline", pprof.Cmdline)
	profiler.HandleFunc("/profile", pprof.Profile)
	profiler.HandleFunc("/symbol", pprof.Symbol)
	profiler.HandleFunc("/trace", pprof.Trace)

	// Manually add support for paths linked to by index page at /debug/pprof/
	for _, item := range []string{"allocs", "block", "heap", "goroutine", "mutex", "threadcreate"} {
		profiler.Handle("/"+item, pprof.Handler(item))
	}
}
