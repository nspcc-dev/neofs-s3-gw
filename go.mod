module github.com/nspcc-dev/neofs-s3-gate

go 1.14

require (
	github.com/aws/aws-sdk-go v1.27.0
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/nspcc-dev/neofs-api-go v1.3.1-0.20201020152448-c8f46f7d9762
	github.com/nspcc-dev/neofs-authmate v0.0.0
	github.com/nspcc-dev/neofs-crypto v0.3.0
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.11.1 // indirect
	github.com/spf13/afero v1.3.3 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	go.uber.org/atomic v1.6.0
	go.uber.org/zap v1.16.0
	golang.org/x/lint v0.0.0-20191125180803-fdd1cda4f05f // indirect
	golang.org/x/net v0.0.0-20200707034311-ab3426394381 // indirect
	golang.org/x/sys v0.0.0-20200806125547-5acd03effb82 // indirect
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/tools v0.0.0-20200123022218-593de606220b // indirect
	google.golang.org/genproto v0.0.0-20200806141610-86f49bd18e98 // indirect
	google.golang.org/grpc v1.33.0
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
)

// temporary
replace (
	github.com/nspcc-dev/neofs-api-go => ../neofs-api
	github.com/nspcc-dev/neofs-authmate => ../neofs-authmate
)
