// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package probe holds probe related files
package probe

import (
	"errors"

	manager "github.com/DataDog/ebpf-manager"
	lib "github.com/cilium/ebpf"

	"github.com/DataDog/datadog-agent/pkg/security/seclog"
)

const (
	rawPacketRouterSelMapName = "raw_packet_router_sel"
)

func lookupRawPacketRouterSelValue(selMap *lib.Map) (active uint32, err error) {
	if selMap == nil {
		return 0, errors.New("raw_packet_router_sel map is nil")
	}
	var key uint32
	var val uint32
	if err := selMap.Lookup(&key, &val); err != nil {
		return 0, err
	}
	return val, nil
}

// LookupRawPacketRouterSel reads BPF map raw_packet_router_sel at key 0 via ebpf-manager. The value
// is the active router buffer index (0 or 1).
func GetActiveRawPacketMapNumber(m *manager.Manager) (active uint32, err error) {
	if m == nil {
		return 0, errors.New("ebpf manager is nil")
	}
	selMap, ok, err := m.GetMap(rawPacketRouterSelMapName)
	if err != nil {
		return 0, err
	}
	if !ok || selMap == nil {
		return 0, errors.New("raw_packet_router_sel map not found")
	}
	return lookupRawPacketRouterSelValue(selMap)
}

// GetRawPacketClassifierMapNameNotUsed returns the prog-array map name for the inactive router buffer
// (the one not selected by raw_packet_router_sel). Userspace loads new tail-call programs there, then
// flips raw_packet_router_sel once per ruleset apply.
func GetRawPacketClassifierMapNameNotUsed(active uint32) string {
	switch active {
	case 0:
		return "raw_packet_classifier_router_1"
	case 1:
		return "raw_packet_classifier_router_0"
	default:
		seclog.Errorf("invalid raw_packet_router_sel value")
		return "raw_packet_classifier_router_0"
	}
}
