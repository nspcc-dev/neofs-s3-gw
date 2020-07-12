package main

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func attachMetrics(v *viper.Viper, l *zap.Logger, r *mux.Router) {
	if !v.GetBool(cfgEnableMetrics) {
		return
	}

	l.Info("enable metrics")
	r.Handle("/metrics", promhttp.Handler())
}
