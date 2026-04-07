// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package fx provides the fx module for the rcprotocoltest component.
package fx

import (
	uberfx "go.uber.org/fx"

	rcprotocoltest "github.com/DataDog/datadog-agent/comp/remote-config/rcprotocoltest/def"
	rcprotocoltestimpl "github.com/DataDog/datadog-agent/comp/remote-config/rcprotocoltest/impl"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Module defines the fx options for this component.
func Module() fxutil.Module {
	return fxutil.Component(
		fxutil.ProvideComponentConstructor(rcprotocoltestimpl.New),
		// rcprotocoltest.Component has no public methods, so nothing in the FX
		// graph depends on it. This invoke forces instantiation so that the
		// lifecycle hooks (Start/Stop) are always registered when this module
		// is included.
		uberfx.Invoke(func(_ rcprotocoltest.Component) {}),
	)
}
