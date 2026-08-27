package authmatesrv

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/nspcc-dev/neofs-s3-gw/internal/version"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

const (
	envPrefix = "S3_AUTHMATESRV"

	defaultShutdownTimeout = 15 * time.Second

	defaultAddress        = "localhost:8090"
	defaultMaxLifetime    = 720 * time.Hour
	defaultMaxRequestSize = 1 << 20 // 1MB
)

const (
	cfgServerAddress = "server.address"
	cfgTLSEnabled    = "server.tls.enabled"
	cfgTLSCertFile   = "server.tls.cert_file"
	cfgTLSKeyFile    = "server.tls.key_file"

	cfgLoggerLevel     = "logger.level"
	cfgLoggerEncoding  = "logger.encoding"
	cfgLoggerTimestamp = "logger.timestamp"

	cfgGates = "gates"

	cfgMaxLifetime    = "limits.max_lifetime"
	cfgMaxRequestSize = "limits.max_request_size"
)

const (
	cmdHelp    = "help"
	cmdVersion = "version"
	cmdConfig  = "config"
)

// NewSettings parses app args.
func NewSettings() *viper.Viper {
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvPrefix(envPrefix)
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AllowEmptyEnv(true)

	flags := pflag.NewFlagSet("commandline", pflag.ExitOnError)
	flags.SortFlags = false

	help := flags.BoolP(cmdHelp, "h", false, "show help")
	versionFlag := flags.BoolP(cmdVersion, "v", false, "show version")
	flags.String(cmdConfig, "", "config path")

	v.SetDefault(cfgLoggerLevel, "info")
	v.SetDefault(cfgLoggerEncoding, "console")
	v.SetDefault(cfgServerAddress, defaultAddress)
	v.SetDefault(cfgMaxLifetime, defaultMaxLifetime)
	v.SetDefault(cfgMaxRequestSize, defaultMaxRequestSize)

	if err := v.BindPFlag(cmdConfig, flags.Lookup(cmdConfig)); err != nil {
		panic(fmt.Errorf("bind flags: %w", err))
	}

	if err := flags.Parse(os.Args); err != nil {
		panic(err)
	}

	switch {
	case *help:
		fmt.Printf("NeoFS S3 Authmate WEB service %s\n", version.Version)
		flags.PrintDefaults()

		fmt.Println()
		fmt.Println("Default environments:")
		fmt.Println()

		allKeys := v.AllKeys()
		slices.Sort(allKeys)

		for _, key := range allKeys {
			defaultValue := v.GetString(key)
			if len(defaultValue) == 0 {
				continue
			}

			fmt.Printf("%s_%s = %s\n", envPrefix, strings.ToUpper(strings.ReplaceAll(key, ".", "_")), defaultValue)
		}

		fmt.Println()
		fmt.Println("Gates preset:")
		fmt.Println()
		fmt.Printf("%s_%s = \"string string ...\"\n", envPrefix, strings.ToUpper(cfgGates))

		os.Exit(0)
	case *versionFlag:
		fmt.Printf("NeoFS S3 Authmate WEB service\nVersion: %s\nGoVersion: %s\n", version.Version, runtime.Version())
		os.Exit(0)
	}

	if v.IsSet(cmdConfig) {
		if err := readConfig(v); err != nil {
			panic(err)
		}
	}

	if v.IsSet(cfgTLSKeyFile) && v.IsSet(cfgTLSCertFile) {
		v.Set(cfgTLSEnabled, true)
	}

	return v
}

func readConfig(v *viper.Viper) error {
	cfgFile, err := os.Open(v.GetString(cmdConfig))
	if err != nil {
		return err
	}

	if err = v.ReadConfig(cfgFile); err != nil {
		return err
	}

	return cfgFile.Close()
}

// NewLogger creates [*zap.Logger] instance.
func NewLogger(v *viper.Viper) *zap.Logger {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(v.GetString(cfgLoggerLevel))); err != nil {
		panic(fmt.Errorf("incorrect logger level configuration %s: %w", v.GetString(cfgLoggerLevel), err))
	}

	encoding := v.GetString(cfgLoggerEncoding)
	if encoding != "console" && encoding != "json" {
		panic(fmt.Errorf("invalid logger encoding value: %s", encoding))
	}

	c := zap.NewProductionConfig()
	c.Level = zap.NewAtomicLevelAt(lvl)
	c.Encoding = encoding
	c.Sampling = nil

	if term.IsTerminal(int(os.Stdout.Fd())) || v.GetBool(cfgLoggerTimestamp) {
		c.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		c.EncoderConfig.EncodeTime = func(_ time.Time, _ zapcore.PrimitiveArrayEncoder) {}
	}

	l, err := c.Build(zap.AddStacktrace(zap.NewAtomicLevelAt(zap.FatalLevel)))
	if err != nil {
		panic(fmt.Sprintf("build zap logger instance: %v", err))
	}

	return l
}
