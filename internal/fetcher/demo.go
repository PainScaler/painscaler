package fetcher

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

// DemoSeedEnv names the env var that, when set to a file path, swaps the ZPA
// fetch path for a JSON-encoded Snapshot loaded from disk. Used by the public
// demo deployment to serve a synthetic tenant without ZPA credentials.
const DemoSeedEnv = "PAINSCALER_DEMO_SEED"

// DemoSeedPath returns the configured demo seed path, or "" if unset.
func DemoSeedPath() string {
	return os.Getenv(DemoSeedEnv)
}

// LoadSnapshotFile reads and decodes a Snapshot JSON file.
func LoadSnapshotFile(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &snap, nil
}

// SeedDemoCache loads the snapshot at path and populates every Cache[T] so
// subsequent CachedFetch calls return the seeded data without hitting ZPA.
// Must be called before any handlers that build indices.
func SeedDemoCache(path string) error {
	snap, err := LoadSnapshotFile(path)
	if err != nil {
		return err
	}
	GetCache().SeedFromSnapshot(snap)
	slog.Info("seeded demo cache",
		slog.String("path", path),
		slog.Int("segments", len(snap.Segments)),
		slog.Int("policies", len(snap.AccessPolicies)),
	)
	return nil
}
