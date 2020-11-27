module github.com/nspcc-dev/neofs-s3-gate

go 1.14

require (
	github.com/aws/aws-sdk-go v1.35.34
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/nspcc-dev/cdn-neofs-sdk v0.0.0
	github.com/nspcc-dev/neofs-api-go v1.20.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	go.uber.org/zap v1.16.0
	google.golang.org/grpc v1.33.1
)

replace github.com/nspcc-dev/cdn-neofs-sdk => ../sdk
