package main

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
)

func attachMetrics(v *viper.Viper, r *mux.Router) {
	if !v.GetBool("metrics") {
		return
	}

	r.Handle("/metrics", promhttp.Handler())
}
