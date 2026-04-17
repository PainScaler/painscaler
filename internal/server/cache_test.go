package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/painscaler/painscaler/internal/index"
)

// TestGetIndex_CoalescesBurstBuilds checks that a burst of concurrent
// getIndex calls within the TTL window only triggers a single BuildIndex
// invocation. Regression guard for the "BuildIndex per handler" waste.
func TestGetIndex_CoalescesBurstBuilds(t *testing.T) {
	var builds atomic.Int64
	s := &Server{
		ctx: context.Background(),
		buildIndexFn: func(ctx context.Context) (*index.Index, error) {
			builds.Add(1)
			return &index.Index{}, nil
		},
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := s.getIndex(); err != nil {
				t.Errorf("getIndex: %v", err)
			}
		})
	}
	wg.Wait()

	if got := builds.Load(); got != 1 {
		t.Fatalf("builds = %d, want 1", got)
	}
}

func TestGetIndex_RebuildsAfterTTL(t *testing.T) {
	var builds atomic.Int64
	s := &Server{
		ctx: context.Background(),
		buildIndexFn: func(ctx context.Context) (*index.Index, error) {
			builds.Add(1)
			return &index.Index{}, nil
		},
	}

	if _, err := s.getIndex(); err != nil {
		t.Fatal(err)
	}
	// Force TTL expiry without sleeping through the real interval.
	s.idxCache.mu.Lock()
	s.idxCache.builtAt = time.Now().Add(-2 * indexTTL)
	s.idxCache.mu.Unlock()

	if _, err := s.getIndex(); err != nil {
		t.Fatal(err)
	}
	if got := builds.Load(); got != 2 {
		t.Fatalf("builds = %d, want 2", got)
	}
}

func TestGetIndex_RebuildsAfterInvalidate(t *testing.T) {
	var builds atomic.Int64
	s := &Server{
		ctx: context.Background(),
		buildIndexFn: func(ctx context.Context) (*index.Index, error) {
			builds.Add(1)
			return &index.Index{}, nil
		},
	}

	if _, err := s.getIndex(); err != nil {
		t.Fatal(err)
	}
	s.invalidateIndex()
	if _, err := s.getIndex(); err != nil {
		t.Fatal(err)
	}
	if got := builds.Load(); got != 2 {
		t.Fatalf("builds = %d, want 2", got)
	}
}
