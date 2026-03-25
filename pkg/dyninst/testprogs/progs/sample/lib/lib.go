// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package lib

var dummy int

//go:noinline
func Foo() {
	dummy++
	InlinedFunc()
}

func InlinedFunc() {
	dummy++
}

// --- Cross-package generics ---

// Box is a generic container type from a different package than main.
type Box[T any] struct {
	Value T
}

// Get returns the value in the Box.
//
//go:noinline
func (b Box[T]) Get() T {
	return b.Value
}

// Set returns a new Box with the given value.
//
//go:noinline
func (b *Box[T]) Set(val T) {
	b.Value = val
}

// Pair is a generic type with two type parameters, defined in lib so it
// can be used by both lib2 and main across package boundaries.
type Pair[K, V any] struct {
	First  K
	Second V
}

// Swap returns a new Pair with the fields reversed.
//
//go:noinline
func (p Pair[K, V]) Swap() Pair[V, K] {
	return Pair[V, K]{First: p.Second, Second: p.First}
}

// Map applies a function to the value in a Box, returning a new Box.
// Tests cross-package generic function with generic type parameter.
//
//go:noinline
func Map[A, B any](box Box[A], f func(A) B) Box[B] {
	return Box[B]{Value: f(box.Value)}
}

// Filter tests a generic function that takes a slice and a predicate.
// When called from another generic function, this tests subdicts.
//
//go:noinline
func Filter[T any](items []T, pred func(T) bool) []T {
	var result []T
	for _, item := range items {
		if pred(item) {
			result = append(result, item)
		}
	}
	return result
}

// Reduce folds a slice into a single value using an accumulator function.
//
//go:noinline
func Reduce[T, R any](items []T, init R, f func(R, T) R) R {
	acc := init
	for _, item := range items {
		acc = f(acc, item)
	}
	return acc
}
