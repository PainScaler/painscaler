# PainScaler

PainScaler is my hate letter to ZScaler.

## What it does

- Full text search across applications, segments, policies, connectors, SCIM groups.
- Access Policy Simulator - a "what-if" tool that runs a SimContext against the policy set and tells you *why* a request would be allowed or denied, not just the verdict.
- Application landscape graph - nodes per layer (SCIM groups, policies, connector groups, segment groups, segments), highlights possible routes.
- Route matrix - every reachable path from a user group to a segment. Answers "Who can hit application X?" and "What can user Y reach?" without you opening 12 tabs in the ZPA console.

## How to run

Two parts:

- **Backend** - Go, uses the Zscaler SDK for all ZPA calls.
- **Frontend** - React + Vite on PatternFly.

Run both on the same host, or better in two containers on a shared network. Use a **read-only** API token. Put a reverse proxy in front for auth. Do not expose this to the internet.

## Scripts

- `go run ./cmd/painscaler` - start the backend.
- `go run ./cmd/seedgen -out snapshot.json` - produce a synthetic snapshot for demo mode (no ZPA tenant needed).
- `cd frontend && yarn dev` - start the frontend with the Vite proxy pointed at the backend.
- `cd frontend && yarn build` - production build. Bundle stats land in `dist/stats.html`.
- `cd frontend && yarn test` - Vitest + RTL + MSW.
- `go run ./apigen` - regenerates the TS client + models from Go handlers.

Run without a ZPA tenant: `PAINSCALER_DEMO_SEED=$PWD/snapshot.json go run ./cmd/painscaler`. See `docs/src/content/docs/deployment/demo-mode.md`.
