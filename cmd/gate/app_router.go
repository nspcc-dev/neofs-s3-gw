package main

import "github.com/gorilla/mux"

const systemPath = "/system"

func newS3Router() *mux.Router {
	// Initialize router. `SkipClean(true)` stops gorilla/mux from
	// normalizing URL path minio/minio#3256
	// avoid URL path encoding minio/minio#8950
	return mux.NewRouter().SkipClean(true).UseEncodedPath()
}
