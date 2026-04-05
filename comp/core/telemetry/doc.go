// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

// Package telemetry is the module root for github.com/DataDog/datadog-agent/comp/core/telemetry.
// The Go packages are in subdirectories:
//   - def/ — component interface (package telemetry)
//   - impl/ — implementation (package telemetryimpl)
//   - impl/noops — noop implementation (package noopsimpl)
//   - fx/ — fx wiring
//   - fx-noop/ — fx wiring for serverless/noop
//   - mock/ — mock for tests
package telemetry
