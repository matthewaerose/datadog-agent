// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.

package telemetry

import def "github.com/DataDog/datadog-agent/comp/core/telemetry/def"

// StatsTelemetrySender is an alias for the canonical type in comp/core/telemetry/def.
type StatsTelemetrySender = def.StatsTelemetrySender

// StatsTelemetryProvider is an alias for the canonical type in comp/core/telemetry/def.
type StatsTelemetryProvider = def.StatsTelemetryProvider

// NewStatsTelemetryProvider creates a new instance of StatsTelemetryProvider
func NewStatsTelemetryProvider(sender StatsTelemetrySender) *StatsTelemetryProvider {
	return def.NewStatsTelemetryProvider(sender)
}

// RegisterStatsSender registers a sender to send the stats metrics
func RegisterStatsSender(sender StatsTelemetrySender) {
	def.RegisterStatsSender(sender)
}

// GetStatsTelemetryProvider gets an instance of the current stats telemetry provider
func GetStatsTelemetryProvider() *StatsTelemetryProvider {
	return def.GetStatsTelemetryProvider()
}
