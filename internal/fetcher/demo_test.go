package fetcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSeedDemoCacheServesFromFetch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, []byte(`{"Segments":[{"id":"seg1","name":"one","enabled":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(DemoSeedEnv, path)

	if err := SeedDemoCache(path); err != nil {
		t.Fatalf("SeedDemoCache: %v", err)
	}

	snap, errs := Fetch(context.Background())
	if len(errs) != 0 {
		t.Fatalf("fetch errs: %v", errs)
	}
	if snap == nil || len(snap.Segments) != 1 || snap.Segments[0].ID != "seg1" {
		t.Fatalf("seeded segment missing from fetch result: %+v", snap)
	}
}

func TestSeedDemoCacheMissingFile(t *testing.T) {
	t.Setenv(DemoSeedEnv, "/does/not/exist.json")
	if err := SeedDemoCache("/does/not/exist.json"); err == nil {
		t.Fatal("expected error for missing seed file")
	}
}
