package main

import (
	"net/http/pprof"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func attachProfiler(v *viper.Viper, l *zap.Logger, r *mux.Router) {
	if !v.GetBool(cfgEnableProfiler) {
		return
	}

	l.Info("enable profiler")

	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
