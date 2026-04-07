// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package clusteragent

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
)

func TestPrintCheckExecutionStatus_ExactMatch(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "my_check",
		InitConfig: integration.Data("{}"),
		Instances:  []integration.Data{integration.Data("{}")},
	}
	// Build the check ID the same way the display function does
	configDigest := config.FastDigest()
	expectedID := string(checkid.BuildID(config.Name, configDigest, config.Instances[0], config.InitConfig))

	stats := types.CLCRunnersStats{
		expectedID: {
			AverageExecutionTime: 100,
			TotalRuns:            50,
			MetricSamples:        10,
			LastExecFailed:       false,
		},
	}

	printCheckExecutionStatus(&buf, config, stats, "")
	output := buf.String()

	assert.Contains(t, output, "[OK]")
	assert.Contains(t, output, "Total Runs: 50")
	assert.Contains(t, output, "Metric Samples: Last Run: 10")
	assert.Contains(t, output, "100ms")
}

func TestPrintCheckExecutionStatus_NamePrefixFallback(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "my_check",
		InitConfig: integration.Data("{}"),
		Instances:  []integration.Data{integration.Data("{}")},
	}

	// Stats with a different hash (simulating secret decryption mismatch)
	stats := types.CLCRunnersStats{
		"my_check:different_hash": {
			AverageExecutionTime: 200,
			TotalRuns:            25,
			LastExecFailed:       true,
			LastError:            "connection refused",
		},
	}

	printCheckExecutionStatus(&buf, config, stats, "")
	output := buf.String()

	assert.Contains(t, output, "[ERROR]")
	assert.Contains(t, output, "Total Runs: 25")
	assert.Contains(t, output, "connection refused")
}

func TestPrintCheckExecutionStatus_MultipleInstances_PrefixFallback(t *testing.T) {
	var buf bytes.Buffer

	// Instances with "name" field set — IDs will be http_check:instance_a:hash, http_check:instance_b:hash
	config := integration.Config{
		Name:       "http_check",
		InitConfig: integration.Data("{}"),
		Instances: []integration.Data{
			integration.Data(`{"name": "instance_a", "url": "http://a.com"}`),
			integration.Data(`{"name": "instance_b", "url": "http://b.com"}`),
		},
	}

	// Stats with same instance names but different hashes (secret decryption mismatch)
	stats := types.CLCRunnersStats{
		"http_check:instance_a:aaaa": {
			AverageExecutionTime: 100,
			TotalRuns:            10,
		},
		"http_check:instance_b:bbbb": {
			AverageExecutionTime: 200,
			TotalRuns:            20,
		},
	}

	printCheckExecutionStatus(&buf, config, stats, "")
	output := buf.String()

	// Both instances matched by checkname:instancename: prefix
	assert.Contains(t, output, "Total Runs: 10")
	assert.Contains(t, output, "Total Runs: 20")

	lines := strings.Split(output, "\n")
	instanceCount := 0
	for _, line := range lines {
		if strings.Contains(line, "Instance ID:") {
			instanceCount++
		}
	}
	assert.Equal(t, 2, instanceCount)
}

func TestPrintCheckExecutionStatus_MultipleInstances_ExactMatch(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "http_check",
		InitConfig: integration.Data("{}"),
		Instances: []integration.Data{
			integration.Data(`{"url": "http://a.com"}`),
			integration.Data(`{"url": "http://b.com"}`),
		},
	}

	// Build exact IDs matching what the display function computes
	configDigest := config.FastDigest()
	id1 := string(checkid.BuildID(config.Name, configDigest, config.Instances[0], config.InitConfig))
	id2 := string(checkid.BuildID(config.Name, configDigest, config.Instances[1], config.InitConfig))

	stats := types.CLCRunnersStats{
		id1: {AverageExecutionTime: 100, TotalRuns: 10},
		id2: {AverageExecutionTime: 200, TotalRuns: 20},
	}

	printCheckExecutionStatus(&buf, config, stats, "")
	output := buf.String()

	// Both instances should match exactly and show stats
	lines := strings.Split(output, "\n")
	instanceCount := 0
	for _, line := range lines {
		if strings.Contains(line, "Instance ID:") {
			instanceCount++
		}
	}
	assert.Equal(t, 2, instanceCount)
	assert.Contains(t, output, "Total Runs: 10")
	assert.Contains(t, output, "Total Runs: 20")
}

func TestPrintCheckExecutionStatus_EmptyStats(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "my_check",
		InitConfig: integration.Data("{}"),
		Instances:  []integration.Data{integration.Data("{}")},
	}

	printCheckExecutionStatus(&buf, config, types.CLCRunnersStats{}, "")
	assert.Empty(t, buf.String())
}

func TestPrintCheckExecutionStatus_NoMatch(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "my_check",
		InitConfig: integration.Data("{}"),
		Instances:  []integration.Data{integration.Data("{}")},
	}

	stats := types.CLCRunnersStats{
		"other_check:abc123": {
			TotalRuns: 100,
		},
	}

	printCheckExecutionStatus(&buf, config, stats, "")
	assert.Empty(t, buf.String())
}

func TestPrintCheckExecutionStatus_FilterByCheckName(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "my_check",
		InitConfig: integration.Data("{}"),
		Instances:  []integration.Data{integration.Data("{}")},
	}

	stats := types.CLCRunnersStats{
		"my_check:abc123": {
			TotalRuns: 100,
		},
	}

	// Filter for a different check name — should print nothing
	printCheckExecutionStatus(&buf, config, stats, "other_check")
	assert.Empty(t, buf.String())

	// Filter for matching check name — should print stats
	buf.Reset()
	printCheckExecutionStatus(&buf, config, stats, "my_check")
	assert.Contains(t, buf.String(), "Total Runs: 100")
}

func TestPrintCheckExecutionStatus_ErrorFields(t *testing.T) {
	var buf bytes.Buffer

	config := integration.Config{
		Name:       "my_check",
		InitConfig: integration.Data("{}"),
		Instances:  []integration.Data{integration.Data("{}")},
	}

	stats := types.CLCRunnersStats{
		"my_check:abc123": {
			LastExecFailed:    true,
			LastError:         "timeout after 30s",
			TotalRuns:         100,
			TotalErrors:       5,
			LastSuccessDate:   1775563775,
			LastExecutionDate: 1775563800000,
		},
	}

	printCheckExecutionStatus(&buf, config, stats, "")
	output := buf.String()

	assert.Contains(t, output, "[ERROR]")
	assert.Contains(t, output, "timeout after 30s")
	assert.Contains(t, output, "Last Execution Date")
	assert.Contains(t, output, "Last Successful Execution Date")
}
