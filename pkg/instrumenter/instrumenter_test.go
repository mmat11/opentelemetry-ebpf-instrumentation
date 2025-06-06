//go:build linux

package instrumenter

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"
)

// Tests fix for https://github.com/grafana/beyla/issues/926
func TestRun_DontPanic(t *testing.T) {
	type testCase struct {
		description    string
		configProvider func() beyla.Config
	}
	testCases := []testCase{{
		description: "otel endpoint but feature excluded",
		configProvider: func() beyla.Config {
			cfg := beyla.DefaultConfig
			cfg.Metrics.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Metrics.CommonEndpoint = "http://localhost"
			return cfg
		},
	}, {
		description: "prom endpoint but feature excluded",
		configProvider: func() beyla.Config {
			cfg := beyla.DefaultConfig
			cfg.Prometheus.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Prometheus.Port = 9090
			return cfg
		},
	}, {
		description: "otel endpoint, otel feature excluded, but prom enabled",
		configProvider: func() beyla.Config {
			cfg := beyla.DefaultConfig
			cfg.Metrics.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Metrics.CommonEndpoint = "http://localhost"
			cfg.Prometheus.Port = 9090
			return cfg
		},
	}, {
		description: "all endpoints, all features excluded",
		configProvider: func() beyla.Config {
			cfg := beyla.DefaultConfig
			cfg.NetworkFlows.Enable = true
			cfg.Prometheus.Port = 9090
			cfg.Prometheus.Features = []string{"application"}
			cfg.Metrics.CommonEndpoint = "http://localhost"
			cfg.Metrics.Features = []string{"application"}
			return cfg
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg := tc.configProvider()
			require.NoError(t, cfg.Validate())

			require.NotPanics(t, func() {
				_ = Run(t.Context(), &cfg)
			})
		})
	}
}

func Test_NetworkEnabled(t *testing.T) {
	t.Setenv("OTEL_EBPF_NETWORK_METRICS", "true")
	cfg, err := beyla.LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Empty(t, mustSkip(cfg))
}
