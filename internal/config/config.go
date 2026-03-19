package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config is the top-level RAVEN configuration, mapping 1:1 to raven.yaml.
type Config struct {
	BMP        BMPConfig        `mapstructure:"bmp"`
	RTR        RTRConfig        `mapstructure:"rtr"`
	Validation ValidationConfig `mapstructure:"validation"`
	Outputs    OutputsConfig    `mapstructure:"outputs"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

type BMPConfig struct {
	Listen string      `mapstructure:"listen"`
	Kafka  *KafkaIngest `mapstructure:"kafka"` // Phase 4 — nil means embedded BMP receiver
}

type KafkaIngest struct {
	Brokers []string `mapstructure:"brokers"`
	Topic   string   `mapstructure:"topic"`
	Group   string   `mapstructure:"group"`
}

type RTRConfig struct {
	Caches         []RTRCacheConfig `mapstructure:"caches"`
	RTRVersion     string           `mapstructure:"rtr-version"`     // "auto", "1", "2"
	ExpireInterval int              `mapstructure:"expire-interval"` // seconds, 0 = use cache default
}

type RTRCacheConfig struct {
	Address    string    `mapstructure:"address"`
	Preference int       `mapstructure:"preference"`
	Transport  string    `mapstructure:"transport"` // "tcp", "tls", "ssh"
	TLS        *TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	CA   string `mapstructure:"ca"`
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
}

type ValidationConfig struct {
	ROV                  bool   `mapstructure:"rov"`
	ASPA                 bool   `mapstructure:"aspa"`
	ASPADefaultProcedure string `mapstructure:"aspa-default-procedure"` // "upstream", "downstream", "auto"
	ASPAASSetBehavior    string `mapstructure:"aspa-as-set-behavior"`   // "unverifiable", "best-effort"
}

type OutputsConfig struct {
	Prometheus *PrometheusOutput `mapstructure:"prometheus"`
	Kafka      *KafkaOutput      `mapstructure:"kafka"`
	File       *FileOutput       `mapstructure:"file"`
}

type PrometheusOutput struct {
	Listen string `mapstructure:"listen"`
	Path   string `mapstructure:"path"`
}

type KafkaOutput struct {
	Brokers []string `mapstructure:"brokers"`
	Topic   string   `mapstructure:"topic"`
}

type FileOutput struct {
	Path     string `mapstructure:"path"`
	Rotation string `mapstructure:"rotation"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load reads the viper-populated config into typed structs and applies defaults.
func Load() (*Config, error) {
	// Defaults
	viper.SetDefault("bmp.listen", ":11019")
	viper.SetDefault("rtr.rtr-version", "auto")
	viper.SetDefault("validation.rov", true)
	viper.SetDefault("validation.aspa", true)
	viper.SetDefault("validation.aspa-default-procedure", "upstream")
	viper.SetDefault("validation.aspa-as-set-behavior", "unverifiable")
	viper.SetDefault("outputs.prometheus.listen", ":9595")
	viper.SetDefault("outputs.prometheus.path", "/metrics")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	// RTR version must be valid
	switch cfg.RTR.RTRVersion {
	case "auto", "1", "2", "":
		// ok
	default:
		return fmt.Errorf("invalid rtr-version %q: must be auto, 1, or 2", cfg.RTR.RTRVersion)
	}

	// ASPA procedure must be valid
	switch cfg.Validation.ASPADefaultProcedure {
	case "upstream", "downstream", "auto", "":
		// ok
	default:
		return fmt.Errorf("invalid aspa-default-procedure %q", cfg.Validation.ASPADefaultProcedure)
	}

	// ASPA AS_SET behavior must be valid
	switch cfg.Validation.ASPAASSetBehavior {
	case "unverifiable", "best-effort", "":
		// ok
	default:
		return fmt.Errorf("invalid aspa-as-set-behavior %q", cfg.Validation.ASPAASSetBehavior)
	}

	return nil
}
