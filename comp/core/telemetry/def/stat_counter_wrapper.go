// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package telemetry

import "sync/atomic"

// StatCounterWrapper is a convenience type that allows for migrating telemetry to
// prometheus Counters while continuing to make the underlying values available for reading
type StatCounterWrapper struct {
	stat    atomic.Int64
	counter Counter
}

// NewStatCounterWrapper returns a new StatCounterWrapper
func NewStatCounterWrapper(component Component, subsystem, name string, tags []string, description string) *StatCounterWrapper {
	return &StatCounterWrapper{
		counter: component.NewCounter(subsystem, name, tags, description),
	}
}

// Inc increments the counter with the given tags value.
func (scw *StatCounterWrapper) Inc(tags ...string) {
	scw.stat.Add(1)
	scw.counter.Inc(tags...)
}

// IncWithTags increments the counter with the given tags value.
func (scw *StatCounterWrapper) IncWithTags(tags map[string]string) {
	scw.stat.Add(1)
	scw.counter.IncWithTags(tags)
}

// Delete deletes the value for the counter with the given tags value.
func (scw *StatCounterWrapper) Delete() {
	scw.stat.Store(0)
	scw.counter.Delete()
}

// Add adds the given value to the counter with the given tags value.
func (scw *StatCounterWrapper) Add(v int64, tags ...string) {
	scw.stat.Add(v)
	scw.counter.Add(float64(v), tags...)
}

// Load atomically loads the wrapped value.
func (scw *StatCounterWrapper) Load() int64 {
	return scw.stat.Load()
}
