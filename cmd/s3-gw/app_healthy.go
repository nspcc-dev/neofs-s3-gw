package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Healthy is a health check interface.
type Healthy interface {
	Status() error
}

const (
	healthyState       = "NeoFS S3 Gateway is "
	hdrContentType     = "Content-Type"
	defaultContentType = "text/plain; charset=utf-8"
)

//nolint:deadcode,unused // TODO
func attachHealthy(r *mux.Router, h Healthy) {
	healthy := r.PathPrefix(systemPath + "/-").
		Subrouter().
		StrictSlash(true)

	healthy.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrContentType, defaultContentType)
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

		w.Header().Set(hdrContentType, defaultContentType)
		w.WriteHeader(code)
		_, _ = fmt.Fprintln(w, healthyState+msg)
	})
}
