-- name: InsertSimulationRun :one
INSERT INTO simulation_runs (context_json, action, matched_rule_id, matched_rule_name, result_json, created_by)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListSimulationRuns :many
SELECT * FROM simulation_runs
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: GetSimulationRun :one
SELECT * FROM simulation_runs
WHERE id = ?;

-- name: DeleteSimulationRun :exec
DELETE FROM simulation_runs
WHERE id = ?;

-- name: CountSimulationRuns :one
SELECT COUNT(*) FROM simulation_runs;
