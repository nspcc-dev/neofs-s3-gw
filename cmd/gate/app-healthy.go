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
	r.HandleFunc("/-/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, healthyState+"ready")
	})

	r.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
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
