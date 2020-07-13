package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

type Healthy interface {
	Status() error
}

const (
	healthyState = "NeoFS S3 Gateway is "
	// defaultContentType = "text/plain; charset=utf-8"
)

func attachHealthy(r *mux.Router, h Healthy) {
	healthy := r.PathPrefix(systemPath + "/-").
		Subrouter().
		StrictSlash(true)

	healthy.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, healthyState+"ready")
	})

	healthy.HandleFunc("/healthy", func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusOK
		msg := "healthy"

		if err := h.Status(); err != nil {
			msg = "unhealthy: " + err.Error()
			code = http.StatusBadRequest
		}

		w.WriteHeader(code)
		_, _ = fmt.Fprintln(w, healthyState+msg)
	})
}
