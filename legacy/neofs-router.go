package legacy

import (
	"github.com/gorilla/mux"
)

func NewRouter(obj ObjectLayer) *mux.Router {
	// Initialize router. `SkipClean(true)` stops gorilla/mux from
	// normalizing URL path minio/minio#3256
	// avoid URL path encoding minio/minio#8950
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()

	// Add healthcheck router
	registerHealthCheckRouter(router)

	// Add server metrics router
	registerMetricsRouter(router)

	// Add API router.
	registerAPIRouter(router, true, true)

	layer := NewGatewayLayerWithLocker(obj)

	// Once endpoints are finalized, initialize the new object api in safe mode.
	globalObjLayerMutex.Lock()
	globalSafeMode = true
	globalObjectAPI = layer
	globalObjLayerMutex.Unlock()

	// Calls all New() for all sub-systems.
	newAllSubsystems()

	// Verify if object layer supports
	// - encryption
	// - compression
	verifyObjectLayerFeatures("gateway NeoFS", layer)

	// Disable safe mode operation, after all initialization is over.
	globalObjLayerMutex.Lock()
	globalSafeMode = false
	globalObjLayerMutex.Unlock()

	return router
}
