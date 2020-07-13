package main

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func attachMetrics(r *mux.Router, v *viper.Viper, l *zap.Logger) {
	if !v.GetBool(cfgEnableMetrics) {
		return
	}

	l.Info("enable metrics")
	r.PathPrefix(systemPath+"/metrics").
		Subrouter().
		StrictSlash(true).
		Handle("", promhttp.Handler())
}
