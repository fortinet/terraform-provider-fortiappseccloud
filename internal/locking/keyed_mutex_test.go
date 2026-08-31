package locking

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistrySerializesSameKey(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	unlock := registry.Lock("same")
	acquired := make(chan struct{})
	go func() {
		defer registry.Lock("same")()
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("same key acquired before unlock")
	case <-time.After(20 * time.Millisecond):
	}
	unlock()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("same key was not acquired after unlock")
	}
}

func TestRegistryAllowsDifferentKeys(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	unlock := registry.Lock("first")
	defer unlock()

	var acquired atomic.Bool
	done := make(chan struct{})
	go func() {
		defer registry.Lock("second")()
		acquired.Store(true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("different key was blocked")
	}
	if !acquired.Load() {
		t.Fatal("different key was not acquired")
	}
}
