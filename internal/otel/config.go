// Package otel provides OpenTelemetry metrics export for RAVEN.
// Only metrics are exported — no traces, no logs.
package otel

import "time"

// OTelConfig controls OpenTelemetry metrics export behaviour.
type OTelConfig struct {
	// Enabled must be true to start the OTel exporter.
	// Defaults to false — zero OTel code runs when disabled.
	Enabled bool `mapstructure:"enabled"`

	// Endpoint is the OTel collector address.
	// Default: "localhost:4317" (gRPC) or "localhost:4318" (HTTP).
	Endpoint string `mapstructure:"endpoint"`

	// Protocol selects the transport: "grpc" (default) or "http".
	Protocol string `mapstructure:"protocol"`

	// Interval is the push interval for the PeriodicReader.
	// Default: 30s.
	Interval time.Duration `mapstructure:"interval"`

	// Headers are optional HTTP/gRPC metadata sent on every export request
	// (e.g. {"Authorization": "Bearer <token>"} for Grafana Cloud).
	Headers map[string]string `mapstructure:"headers"`

	// Insecure disables TLS verification. Default: true (local collector).
	Insecure bool `mapstructure:"insecure"`

	// ResourceAttributes are added as OTel resource attributes.
	// Example: {"service.name": "raven", "deployment.env": "prod"}.
	ResourceAttributes map[string]string `mapstructure:"resource_attributes"`
}

// applyDefaults fills zero-valued fields with their documented defaults.
func (c *OTelConfig) applyDefaults() {
	if c.Endpoint == "" {
		c.Endpoint = "localhost:4317"
	}
	if c.Protocol == "" {
		c.Protocol = "grpc"
	}
	if c.Interval == 0 {
		c.Interval = 30 * time.Second
	}
}
