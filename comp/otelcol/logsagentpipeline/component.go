// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package logsagentpipeline provides the logs agent pipeline component.
package logsagentpipeline

import logsagentpipelinedef "github.com/DataDog/datadog-agent/comp/otelcol/logsagentpipeline/def"

// team: opentelemetry-agent

// Component is the component type.
type Component = logsagentpipelinedef.Component

// LogsAgent is a compat version of component for non fx usage
type LogsAgent = logsagentpipelinedef.LogsAgent
