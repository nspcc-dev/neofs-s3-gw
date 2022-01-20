package main

import "github.com/gorilla/mux"

const systemPath = "/system"

func newS3Router() *mux.Router {
	// Initialize router
	return mux.NewRouter().SkipClean(true).UseEncodedPath()
}
