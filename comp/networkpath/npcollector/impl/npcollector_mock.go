// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build test

package npcollectorimpl

import (
	"iter"

	"go.uber.org/fx"

	npmodel "github.com/DataDog/datadog-agent/comp/networkpath/npcollector/model"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

type npCollectorMock struct{}

func (s *npCollectorMock) ScheduleNetworkPathTests(_conns iter.Seq[npmodel.NetworkPathConnection]) {}

// MockModule defines the fx options for the mock npcollector component.
func MockModule() fxutil.Module {
	return fxutil.Component(
		fx.Provide(NewMock),
	)
}

// Module defines the fx options for the npcollector component.
func Module() fxutil.Module {
	return fxutil.Component(
		fxutil.ProvideComponentConstructor(NewNpCollector),
	)
}

// NewMock creates a mock npcollector component.
func NewMock() Provides {
	// Mock initialization
	return Provides{
		Comp: &npCollectorMock{},
	}
}
