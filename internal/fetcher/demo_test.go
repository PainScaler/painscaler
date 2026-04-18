package fetcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchDemoSeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, []byte(`{"Segments":[],"AccessPolicies":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DemoSeedEnv, path)

	snap, errs := Fetch(context.Background())
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if snap == nil {
		t.Fatal("nil snapshot")
	}
	if snap.Segments == nil {
		t.Fatalf("segments should decode to empty slice, got nil")
	}
}

func TestFetchDemoSeedMissingFile(t *testing.T) {
	t.Setenv(DemoSeedEnv, "/does/not/exist.json")
	snap, errs := Fetch(context.Background())
	if snap != nil {
		t.Fatalf("expected nil snapshot on load failure")
	}
	if len(errs) == 0 {
		t.Fatalf("expected FetchError")
	}
	if errs[0].Resource != "demo_seed" {
		t.Fatalf("want resource=demo_seed, got %q", errs[0].Resource)
	}
}
