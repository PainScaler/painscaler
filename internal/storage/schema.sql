CREATE TABLE IF NOT EXISTS simulation_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    context_json TEXT     NOT NULL,
    action       TEXT     NOT NULL,
    matched_rule_id   TEXT,
    matched_rule_name TEXT,
    result_json  TEXT     NOT NULL,
    created_by   TEXT
);
