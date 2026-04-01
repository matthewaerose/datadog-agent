// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.

//go:build otlp

package configcheck

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configmock "github.com/DataDog/datadog-agent/pkg/config/mock"
	"github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/config/nodetreemodel"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/config/viperconfig"
)

func TestIsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		envVars  map[string]string
		expected bool
	}{
		{
			name:     "empty config",
			yaml:     "",
			expected: false,
		},
		{
			name: "otlp_config section missing",
			yaml: `
some_other_config: value
`,
			expected: false,
		},
		{
			name: "otlp_config exists but empty",
			yaml: `
otlp_config:
`,
			expected: false,
		},
		{
			name: "otlp_config exists but receiver key missing",
			yaml: `
otlp_config:
  other_key: value
`,
			expected: false,
		},
		{
			name: "receiver section exists but empty",
			yaml: `
otlp_config:
  receiver:
`,
			expected: true,
		},
		{
			name: "receiver section exists but null",
			yaml: `
otlp_config:
  receiver: null
`,
			expected: true,
		},
		{
			name: "receiver section with protocols but empty",
			yaml: `
otlp_config:
  receiver:
    protocols:
`,
			expected: true,
		},
		{
			name: "receiver section with protocols grpc and http empty",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc:
      http:
`,
			expected: true,
		},
		{
			name: "receiver section with protocols grpc and http null",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc: null
      http: null
`,
			expected: true,
		},
		{
			name: "receiver section with full grpc configuration",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
`,
			expected: true,
		},
		{
			name: "receiver section with full http configuration",
			yaml: `
otlp_config:
  receiver:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
`,
			expected: true,
		},
		{
			name: "receiver section with both grpc and http configuration",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
`,
			expected: true,
		},
		{
			name: "empty config with env var setting grpc endpoint",
			yaml: "",
			envVars: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT": "0.0.0.0:9993",
			},
			expected: true,
		},
		{
			name: "empty config with env var setting http endpoint",
			yaml: "",
			envVars: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT": "0.0.0.0:9994",
			},
			expected: true,
		},
		{
			name: "empty config with multiple env vars",
			yaml: "",
			envVars: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT":          "0.0.0.0:9993",
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT":          "0.0.0.0:9994",
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_MAX_RECV_MSG_SIZE": "4194304",
			},
			expected: true,
		},
		{
			name: "config with receiver and env var override",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
`,
			envVars: map[string]string{
				"DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT": "0.0.0.0:9994",
			},
			expected: true,
		},
		{
			name: "env var for non-receiver otlp config should not enable",
			yaml: "",
			envVars: map[string]string{
				"DD_OTLP_CONFIG_TRACES_ENABLED": "true",
				"DD_OTLP_CONFIG_LOGS_ENABLED":   "true",
			},
			expected: false,
		},
		{
			name: "otlp_config with other sections but no receiver",
			yaml: `
otlp_config:
  traces:
    enabled: true
  logs:
    enabled: true
`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			// Create mock config
			cfg := configmock.New(t)
			pkgconfigsetup.OTLP(cfg)

			// Create temporary file and read config from it
			if tt.yaml != "" {
				tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
				require.NoError(t, err, "Failed to create temp file")
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(tt.yaml)
				require.NoError(t, err, "Failed to write YAML to temp file")
				tmpFile.Close()

				cfg.SetConfigFile(tmpFile.Name())
				err = cfg.ReadInConfig()
				require.NoError(t, err, "Failed to read YAML config")
			}

			result := IsEnabled(cfg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasSectionEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		section  string
		expected bool
	}{
		{
			name: "section exists with nested empty map",
			yaml: `
otlp_config:
  receiver:
    nested:
`,
			section:  "receiver",
			expected: true,
		},
		{
			name: "section exists with deeply nested structure",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: localhost:4317
        tls:
          insecure: true
`,
			section:  "receiver",
			expected: true,
		},
		{
			name: "section with boolean value",
			yaml: `
otlp_config:
  receiver: true
`,
			section:  "receiver",
			expected: true,
		},
		{
			name: "section with string value",
			yaml: `
otlp_config:
  receiver: some_string_value
`,
			section:  "receiver",
			expected: true,
		},
		{
			name: "section with numeric value",
			yaml: `
otlp_config:
  receiver: 12345
`,
			section:  "receiver",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configmock.New(t)
			pkgconfigsetup.OTLP(cfg)

			tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
			require.NoError(t, err, "Failed to create temp file")
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.yaml)
			require.NoError(t, err, "Failed to write YAML to temp file")
			tmpFile.Close()

			cfg.SetConfigFile(tmpFile.Name())
			err = cfg.ReadInConfig()
			require.NoError(t, err, "Failed to read YAML config")

			result := hasSection(cfg, tt.section)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsEnabledConsistencyWithReadConfigSection(t *testing.T) {
	// This test ensures that IsEnabled is consistent with ReadConfigSection behavior
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "receiver section exists but empty",
			yaml: `
otlp_config:
  receiver:
`,
		},
		{
			name: "receiver section exists but null",
			yaml: `
otlp_config:
  receiver: null
`,
		},
		{
			name: "receiver section with configuration",
			yaml: `
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configmock.New(t)
			pkgconfigsetup.OTLP(cfg)

			tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
			require.NoError(t, err, "Failed to create temp file")
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.yaml)
			require.NoError(t, err, "Failed to write YAML to temp file")
			tmpFile.Close()

			cfg.SetConfigFile(tmpFile.Name())
			err = cfg.ReadInConfig()
			require.NoError(t, err, "Failed to read YAML config")

			// IsEnabled should return true if ReadConfigSection can find the receiver key
			isEnabled := IsEnabled(cfg)
			configSection := ReadConfigSection(cfg, pkgconfigsetup.OTLPSection)
			_, hasReceiverKey := configSection.ToStringMap()[pkgconfigsetup.OTLPReceiverSubSectionKey]

			assert.Equal(t, hasReceiverKey, isEnabled,
				"IsEnabled should be consistent with ReadConfigSection's ability to find receiver key")
		})
	}
}

func TestReadConfigSection(t *testing.T) {
	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  traces:
    enabled: true
    infra_attributes:
      enabled: false
  logs:
    enabled: true
  receiver:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	expectMap := map[string]interface{}{
		"logs::enabled":                       true,
		"receiver::protocols::grpc::endpoint": "0.0.0.0:4317",
		"traces::enabled":                     true,
		"traces::infra_attributes::enabled":   false,
	}

	assert.Equal(t, expectMap, configSection)
}

func TestReadConfigEmptySection(t *testing.T) {
	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  traces:
    enabled: true
  logs:
    enabled: true
  receiver:
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	expectMap := map[string]interface{}{
		"logs::enabled":   true,
		"receiver":        nil,
		"traces::enabled": true,
	}

	assert.Equal(t, expectMap, configSection)
}

func TestReadConfigSectionEnvVars(t *testing.T) {
	t.Setenv("TEST_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT", "0.0.0.0:9999")
	t.Setenv("TEST_OTLP_CONFIG_DEBUG_VERBOSITY", "normal")

	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  traces:
    enabled: true
  logs:
    enabled: true
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	// TEST_ prefix env vars don't match the DD_ config prefix, so they have no effect.
	expectMap := map[string]interface{}{
		"logs::enabled":   true,
		"traces::enabled": true,
	}

	assert.Equal(t, expectMap, configSection)
}

func TestReadConfigSectionDDEnvVars(t *testing.T) {
	t.Setenv("DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT", "0.0.0.0:9999")
	t.Setenv("DD_OTLP_CONFIG_DEBUG_VERBOSITY", "normal")

	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  traces:
    enabled: true
  logs:
    enabled: true
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	expectMap := map[string]interface{}{
		"debug::verbosity":                    "normal",
		"logs::enabled":                       true,
		"receiver::protocols::grpc::endpoint": "0.0.0.0:9999",
		"traces::enabled":                     true,
	}

	assert.Equal(t, expectMap, configSection)
}

func TestReadConfigSectionNoUserConfig(t *testing.T) {
	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	configSection := readConfigSection(cfg, "otlp_config")

	assert.Empty(t, configSection, "defaults should not leak into readConfigSection output")
}

func TestReadConfigSectionSingleOverride(t *testing.T) {
	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  metrics:
    histograms:
      mode: "nobuckets"
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	expectMap := map[string]interface{}{
		"metrics::histograms::mode": "nobuckets",
	}

	assert.Equal(t, expectMap, configSection)
}

func TestReadConfigSectionCORSArrays(t *testing.T) {
	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  receiver:
    protocols:
      http:
        cors:
          allowed_origins:
            - "http://example.com"
          allowed_headers:
            - "Authorization"
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	assert.Equal(t, []string{"http://example.com"}, configSection["receiver::protocols::http::cors::allowed_origins"])
	assert.Equal(t, []string{"Authorization"}, configSection["receiver::protocols::http::cors::allowed_headers"])
}

func TestReadConfigSectionEmptyProtocolDeclaration(t *testing.T) {
	cfg := configmock.New(t)
	pkgconfigsetup.OTLP(cfg)

	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err, "Failed to create temp file")
	defer os.Remove(tmpFile.Name())

	yamlData := `
otlp_config:
  receiver:
    protocols:
      grpc:
`
	_, err = tmpFile.WriteString(yamlData)
	require.NoError(t, err, "Failed to write YAML to temp file")
	tmpFile.Close()

	cfg.SetConfigFile(tmpFile.Name())
	err = cfg.ReadInConfig()
	require.NoError(t, err, "Failed to read YAML config")

	configSection := readConfigSection(cfg, "otlp_config")

	expectMap := map[string]interface{}{
		"receiver::protocols::grpc": nil,
	}

	assert.Equal(t, expectMap, configSection)
}

// TestViperNTMHasSectionDivergenceOnNullLeaf demonstrates that Viper and NTM
// (nodetreemodel) config backends disagree on HasSection for a YAML null leaf.
//
// Given the same YAML:
//
//	otlp_config:
//	  logs:
//	    enabled:          # <-- YAML null
//
// Viper treats the nil-valued "enabled" map entry as a section marker and
// returns HasSection=true, while NTM correctly identifies it as a leaf and
// returns HasSection=false.
//
// Both backends agree that IsConfigured is false (a nil file value is not
// a real user configuration).
//
// This divergence caused a CI failure: the readConfigSection filter
// (HasSection || IsConfigured) included the entry on Viper but excluded it
// on NTM, producing different outputs for the same input YAML.
func TestViperNTMHasSectionDivergenceOnNullLeaf(t *testing.T) {
	const yamlData = `
otlp_config:
  logs:
    enabled:
`
	const key = "otlp_config.logs.enabled"

	newBackendConfig := func(t *testing.T, constructor func(string, string, *strings.Replacer) model.BuildableConfig) model.BuildableConfig {
		cfg := constructor("datadog", "DD", strings.NewReplacer(".", "_"))
		pkgconfigsetup.OTLP(cfg)
		cfg.BuildSchema()

		tmpFile, err := os.CreateTemp("", "test-null-leaf-*.yaml")
		require.NoError(t, err)
		t.Cleanup(func() { os.Remove(tmpFile.Name()) })

		_, err = tmpFile.WriteString(yamlData)
		require.NoError(t, err)
		tmpFile.Close()

		cfg.SetConfigFile(tmpFile.Name())
		require.NoError(t, cfg.ReadInConfig())
		return cfg
	}

	viperCfg := newBackendConfig(t, viperconfig.NewViperConfig)
	ntmCfg := newBackendConfig(t, nodetreemodel.NewNodeTreeConfig)

	// Both backends agree: IsConfigured is false for a null YAML leaf.
	// Neither considers a nil value from the config file as user-configured.
	assert.False(t, viperCfg.IsConfigured(key), "Viper: IsConfigured must be false for null leaf")
	assert.False(t, ntmCfg.IsConfigured(key), "NTM:   IsConfigured must be false for null leaf")

	// HasSection DIVERGES: this is the root cause of the CI failure.
	// Viper incorrectly treats a nil-valued leaf as a section.
	assert.True(t, viperCfg.HasSection(key), "Viper: HasSection returns true for null leaf (BUG: treats nil map entry as section)")
	assert.False(t, ntmCfg.HasSection(key), "NTM:   HasSection returns false for null leaf (correct: it's a leaf, not a section)")

	// Consequence: readConfigSection produces different output per backend.
	viperResult := readConfigSection(viperCfg, "otlp_config.logs")
	ntmResult := readConfigSection(ntmCfg, "otlp_config.logs")

	// Viper: HasSection=true lets the entry pass the filter; Get() resolves
	// the nil to the registered default (false).
	assert.Equal(t, map[string]interface{}{"enabled": false}, viperResult,
		"Viper: null leaf passes HasSection filter → entry included with default value")

	// NTM: both HasSection=false and IsConfigured=false → entry filtered out.
	assert.Equal(t, map[string]interface{}{}, ntmResult,
		"NTM: null leaf filtered out → empty map")

	// This divergence is why YAML fixtures must use explicit values
	// (e.g. "enabled: false") instead of null leaves ("enabled:").
}
