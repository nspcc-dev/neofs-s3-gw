package legacy

import (
	"github.com/gorilla/mux"
)

func AttachS3API(r *mux.Router, obj ObjectLayer) {
	// Add healthcheck router
	registerHealthCheckRouter(r)

	// Add server metrics router
	registerMetricsRouter(r)

	// Add API router.
	registerAPIRouter(r, true, true)

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
}
