package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// newLogger constructs a zap.Logger instance for the current application.
// Panics on failure.
//
// Logger is built from zap's production logging configuration with:
//  * parameterized level (debug by default)
//  * console encoding
//  * ISO8601 time encoding
//
// Logger records a stack trace for all messages at or above fatal level.
//
// See also zapcore.Level, zap.NewProductionConfig, zap.AddStacktrace.
func newLogger(v *viper.Viper) *zap.Logger {
	var lvl zapcore.Level
	lvlStr := v.GetString(cfgLoggerLevel)

	err := lvl.UnmarshalText([]byte(lvlStr))
	if err != nil {
		panic(fmt.Sprintf("incorrect logger level configuration %s (%v), "+
			"value should be one of %v", lvlStr, err, [...]zapcore.Level{
			zapcore.DebugLevel,
			zapcore.InfoLevel,
			zapcore.WarnLevel,
			zapcore.ErrorLevel,
			zapcore.DPanicLevel,
			zapcore.PanicLevel,
			zapcore.FatalLevel,
		}))
	}

	c := zap.NewProductionConfig()
	c.Level = zap.NewAtomicLevelAt(lvl)
	c.Encoding = "console"
	c.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	l, err := c.Build(
		zap.AddStacktrace(zap.NewAtomicLevelAt(zap.FatalLevel)),
	)
	if err != nil {
		panic(fmt.Sprintf("build zap logger instance: %v", err))
	}

	return l
}

func main() {
	var (
		v    = newSettings()
		l    = newLogger(v)
		g, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		a    = newApp(g, l, v)
	)

	go a.Server(g)

	a.Wait()
}
