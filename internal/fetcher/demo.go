package fetcher

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

// DemoSeedEnv names the env var that, when set to a file path, makes Fetch
// return the JSON-encoded Snapshot at that path instead of calling ZPA. Used
// by the public demo deployment to serve a scrubbed synthetic tenant.
const DemoSeedEnv = "PAINSCALER_DEMO_SEED"

// DemoSeedPath returns the configured demo seed path, or "" if unset.
func DemoSeedPath() string {
	return os.Getenv(DemoSeedEnv)
}

func loadDemoSnapshot(path string) (*Snapshot, []FetchError) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, []FetchError{{Resource: "demo_seed", Err: fmt.Errorf("read %s: %w", path, err)}}
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, []FetchError{{Resource: "demo_seed", Err: fmt.Errorf("unmarshal %s: %w", path, err)}}
	}
	slog.Info("loaded demo snapshot",
		slog.String("path", path),
		slog.Int("segments", len(snap.Segments)),
		slog.Int("policies", len(snap.AccessPolicies)),
	)
	return &snap, nil
}
