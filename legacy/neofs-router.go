package legacy

import (
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func AttachS3API(r *mux.Router, obj ObjectLayer, l *zap.Logger) {
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

	// Handle gateway specific env
	gatewayHandleEnvVars()

	// Set system resources to maximum.
	if err := setMaxResources(); err != nil {
		l.Warn("could not set max resources",
			zap.Error(err))
	}
}
