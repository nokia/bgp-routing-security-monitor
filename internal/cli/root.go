package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Set via ldflags at build time (see Makefile)
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

var cfgFile string
var addr string

var rootCmd = &cobra.Command{
	Use:   "raven",
	Short: "RAVEN — Routing Analysis, Validation, and Event Network",
	Long: `RAVEN correlates live BMP feeds, RPKI ROV, and ASPA path validation
into a unified, operator-facing workflow.

Ravens see what you can't.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./raven.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level: debug, info, warn, error")
	rootCmd.PersistentFlags().String("log-format", "json", "log format: json, text")
	rootCmd.PersistentFlags().StringVar(&addr, "address", "localhost:11020", "RAVEN daemon address for CLI queries")

	// Bind flags to viper
	viper.BindPFlag("logging.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("logging.format", rootCmd.PersistentFlags().Lookup("log-format"))

	// Register subcommands
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(peersCmd)
	rootCmd.AddCommand(routesCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(watchCmd)
	rootCmd.AddCommand(newWhatIfCmd(&addr))
	rootCmd.AddCommand(newASPACmd(&addr))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("raven")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/raven")
	}

	viper.SetEnvPrefix("RAVEN")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
		}
	}
}

// initLogger creates a structured logger based on config.
func initLogger() *slog.Logger {
	level := slog.LevelInfo
	switch viper.GetString("logging.level") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if viper.GetString("logging.format") == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}