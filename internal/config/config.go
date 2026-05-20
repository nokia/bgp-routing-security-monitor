package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level RAVEN configuration, mapping 1:1 to raven.yaml.
type Config struct {
	BMP         BMPConfig         `mapstructure:"bmp"`
	RTR         RTRConfig         `mapstructure:"rtr"`
	Validation  ValidationConfig  `mapstructure:"validation"`
	Outputs     OutputsConfig     `mapstructure:"outputs"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Events      EventsConfig      `mapstructure:"events"`
	Persistence PersistenceConfig `mapstructure:"persistence"`
}

// PersistenceConfig controls warm-start snapshot behaviour.
type PersistenceConfig struct {
	// Enabled must be true to write/read snapshots. Defaults to false
	// so existing deployments are unaffected.
	Enabled bool `mapstructure:"enabled"`
	// SnapshotDir is the directory for snapshot files.
	// Supports ~ expansion. Default: ~/.raven/snapshots
	SnapshotDir string `mapstructure:"snapshot_dir"`
	// StaleEvictionTimeout is how long to wait after startup before
	// evicting routes that were restored from a snapshot but never
	// confirmed by a live BMP message.
	StaleEvictionTimeout time.Duration `mapstructure:"stale_eviction_timeout"`
}

// EventsConfig configures the Phase 3 active-response event engine.
type EventsConfig struct {
	Rules []RuleConfig `mapstructure:"rules"`
}

// RuleConfig is the YAML representation of a single event rule.
type RuleConfig struct {
	Name    string        `mapstructure:"name"`
	Trigger TriggerConfig `mapstructure:"trigger"`
	// Cooldown is a Go duration string (e.g. "60s", "5m"). Empty means no cooldown.
	Cooldown string         `mapstructure:"cooldown"`
	Actions  []ActionConfig `mapstructure:"actions"`
}

// TriggerConfig is the YAML representation of a trigger.
// The Type field selects the trigger kind: posture, posture_change, prefix,
// asn, protected_asn, cache_unhealthy, or compound.
type TriggerConfig struct {
	Type     string   `mapstructure:"type"`
	Postures []string `mapstructure:"postures"`
	Prefix   string   `mapstructure:"prefix"`
	ASNs     []uint32 `mapstructure:"asns"`
	// ASNMatch controls how the asn trigger matches: "origin" (default) checks
	// only the last ASN in the AS path; "path" matches any ASN in the full path.
	ASNMatch string `mapstructure:"asn_match"`
	// Operator is used by compound triggers: "and" or "or".
	Operator string `mapstructure:"operator"`
	// Triggers holds sub-triggers for compound triggers.
	Triggers []TriggerConfig `mapstructure:"triggers"`
}

// ActionConfig is the YAML representation of an action.
// The Type field selects the action kind: log, webhook, or flowspec.
type ActionConfig struct {
	Type string `mapstructure:"type"`
	// Level is used by the log action: "info", "warn", or "error".
	Level string `mapstructure:"level"`
	// URL is used by the webhook action.
	URL string `mapstructure:"url"`
	// Secret enables HMAC-SHA256 signing for the webhook action.
	Secret string `mapstructure:"secret"`
	// Timeout is a Go duration string for the per-attempt HTTP timeout (webhook action).
	Timeout string `mapstructure:"timeout"`
	// MaxAttempts is the maximum number of delivery attempts (webhook action).
	MaxAttempts int `mapstructure:"max_attempts"`
	// Headers are additional HTTP headers to include in webhook requests.
	Headers map[string]string `mapstructure:"headers"`
	// DryRun is used by the flowspec action to suppress GoBGP injection.
	DryRun bool `mapstructure:"dry_run"`
	// GoBGPAddress is the GoBGP gRPC management endpoint for the flowspec action.
	GoBGPAddress string `mapstructure:"gobgp_address"`
	// MaxRules is the maximum number of concurrently active flowspec rules.
	MaxRules int `mapstructure:"max_rules"`
	// TTL is a Go duration string for the per-rule lifetime (flowspec action).
	TTL string `mapstructure:"ttl"`
	// RuleAction is the Flowspec traffic action: "drop" or "rate-limit".
	RuleAction string `mapstructure:"rule_action"`
	// ReaperInterval is a Go duration string for the flowspec rule reaper cadence.
	ReaperInterval string `mapstructure:"reaper_interval"`
	// ApprovalWebhook is an optional URL for flowspec injection approval.
	ApprovalWebhook string `mapstructure:"approval_webhook"`
	// ApprovalTimeout is a Go duration string for the approval webhook HTTP timeout.
	ApprovalTimeout string `mapstructure:"approval_timeout"`
}

// WebhookActionConfig collects the webhook-specific fields from ActionConfig.
// It is populated by buildAction in the events package.
type WebhookActionConfig struct {
	URL         string            `mapstructure:"url"`
	Secret      string            `mapstructure:"secret"`
	Timeout     string            `mapstructure:"timeout"`
	MaxAttempts int               `mapstructure:"max_attempts"`
	Headers     map[string]string `mapstructure:"headers"`
}

// FlowspecActionConfig collects the flowspec-specific fields from ActionConfig.
// It is populated by buildAction in the events package.
type FlowspecActionConfig struct {
	// GoBGPAddress is the GoBGP gRPC management endpoint. When empty, no GoBGP
	// client is created and live injection is unavailable.
	GoBGPAddress string `mapstructure:"gobgp_address"`
	// MaxRules is the maximum number of concurrently active rules (default 100; 0 = unlimited).
	MaxRules int `mapstructure:"max_rules"`
	// TTL is a Go duration string for the per-rule lifetime (default "1h").
	TTL string `mapstructure:"ttl"`
	// RuleAction is the Flowspec action: "drop" or "rate-limit" (default "drop").
	RuleAction string `mapstructure:"rule_action"`
	// DryRun logs rules without injecting them into GoBGP.
	DryRun bool `mapstructure:"dry_run"`
	// ReaperInterval is a Go duration string for how often expired rules are withdrawn (default "30s").
	ReaperInterval string `mapstructure:"reaper_interval"`
	// ApprovalWebhook is an optional URL to POST for injection approval.
	ApprovalWebhook string `mapstructure:"approval_webhook"`
	// ApprovalTimeout is a Go duration string for the approval webhook HTTP timeout (default "10s").
	ApprovalTimeout string `mapstructure:"approval_timeout"`
}

type BMPConfig struct {
	Listen string       `mapstructure:"listen"`
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
	Address    string     `mapstructure:"address"`
	Preference int        `mapstructure:"preference"`
	Transport  string     `mapstructure:"transport"` // "tcp", "tls", "ssh"
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
	OTel       OTelOutputConfig  `mapstructure:"otel"`
}

// OTelOutputConfig is the YAML representation of the OTel output.
// It maps 1:1 to internal/otel.OTelConfig.
type OTelOutputConfig struct {
	Enabled            bool              `mapstructure:"enabled"`
	Endpoint           string            `mapstructure:"endpoint"`
	Protocol           string            `mapstructure:"protocol"`
	Interval           time.Duration     `mapstructure:"interval"`
	Headers            map[string]string `mapstructure:"headers"`
	Insecure           bool              `mapstructure:"insecure"`
	ResourceAttributes map[string]string `mapstructure:"resource_attributes"`
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
	viper.SetDefault("outputs.otel.enabled", false)
	viper.SetDefault("outputs.otel.endpoint", "localhost:4317")
	viper.SetDefault("outputs.otel.protocol", "grpc")
	viper.SetDefault("outputs.otel.interval", 30*time.Second)
	viper.SetDefault("outputs.otel.insecure", true)
	viper.SetDefault("outputs.otel.resource_attributes", map[string]string{
		"service.name":    "raven",
		"service.version": "v0.1.0",
	})
	viper.SetDefault("persistence.enabled", false)
	viper.SetDefault("persistence.snapshot_dir", "~/.raven/snapshots")
	viper.SetDefault("persistence.stale_eviction_timeout", 5*time.Minute)
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
