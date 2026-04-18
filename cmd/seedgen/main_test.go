package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/painscaler/painscaler/internal/fetcher"
)

func TestBuildRoundtripsThroughFetcher(t *testing.T) {
	snap := build()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fetcher.DemoSeedEnv, path)

	if err := fetcher.SeedDemoCache(path); err != nil {
		t.Fatalf("SeedDemoCache: %v", err)
	}

	got, errs := fetcher.Fetch(context.Background())
	if len(errs) != 0 {
		t.Fatalf("fetch errs: %v", errs)
	}
	if got == nil {
		t.Fatal("nil snapshot")
	}

	if len(got.Segments) != len(snap.Segments) {
		t.Errorf("segments: got %d, want %d", len(got.Segments), len(snap.Segments))
	}
	if len(got.AccessPolicies) != len(snap.AccessPolicies) {
		t.Errorf("policies: got %d, want %d", len(got.AccessPolicies), len(snap.AccessPolicies))
	}
	if len(got.SegmentGroups) != len(snap.SegmentGroups) {
		t.Errorf("segment groups: got %d, want %d", len(got.SegmentGroups), len(snap.SegmentGroups))
	}
	if len(got.ScimGroups) != len(snap.ScimGroups) {
		t.Errorf("scim groups: got %d, want %d", len(got.ScimGroups), len(snap.ScimGroups))
	}
}
