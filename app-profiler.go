package main

import (
	"net/http/pprof"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

func attachProfiler(v *viper.Viper, r *mux.Router) {
	if !v.GetBool("pprof") {
		return
	}

	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
