module github.com/nspcc-dev/neofs-s3-gw

go 1.16

require (
	github.com/aws/aws-sdk-go v1.37.9
	github.com/bluele/gcache v0.0.2
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/minio/minio-go/v7 v7.0.13
	github.com/nspcc-dev/neo-go v0.97.2
	github.com/nspcc-dev/neofs-api-go v1.29.0
	github.com/nspcc-dev/neofs-sdk-go v0.0.0-20210728122117-c55ae2c13f78
	github.com/prometheus/client_golang v1.11.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	go.uber.org/zap v1.18.1
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
)

replace github.com/nspcc-dev/neofs-sdk-go => ../neofs-sdk-go
