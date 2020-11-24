package main

import (
	"github.com/nspcc-dev/cdn-neofs-sdk/grace"
	"github.com/nspcc-dev/cdn-neofs-sdk/logger"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func newLogger(v *viper.Viper) *zap.Logger {
	options := []logger.Option{
		logger.WithLevel(v.GetString("logger.level")),
		logger.WithTraceLevel(v.GetString("logger.trace_level")),

		logger.WithFormat(v.GetString("logger.format")),

		logger.WithSamplingInitial(v.GetInt("logger.sampling.initial")),
		logger.WithSamplingThereafter(v.GetInt("logger.sampling.thereafter")),

		logger.WithAppName(v.GetString("app_name")),
		logger.WithAppVersion(v.GetString("app_version")),
	}

	if v.GetBool("logger.no_caller") {
		options = append(options, logger.WithoutCaller())
	}

	if v.GetBool("logger.no_disclaimer") {
		options = append(options, logger.WithoutDisclaimer())
	}

	l, err := logger.New(options...)
	if err != nil {
		panic(err)
	}

	return l
}

func main() {
	var (
		v = newSettings()
		l = newLogger(v)
		g = grace.Context(l)
		a = newApp(g, l, v)
	)

	go a.Server(g)
	go a.Worker(g)

	a.Wait()
}
