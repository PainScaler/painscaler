package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"net/url"
	"time"

	"github.com/painscaler/painscaler/internal/simulator"
	_ "modernc.org/sqlite"
)

// Pool defaults. SQLite is single-writer, so keeping the pool small avoids
// spurious SQLITE_BUSY under contention while still allowing parallel reads
// once WAL is enabled.
const (
	storeMaxOpenConns    = 4
	storeMaxIdleConns    = 2
	storeConnMaxIdleTime = 5 * time.Minute
)

// buildDSN constructs a modernc.org/sqlite DSN with pragmas applied on every
// new connection:
//   - journal_mode=WAL:   readers do not block the writer
//   - synchronous=NORMAL: safe under WAL, avoids per-commit fsync
//   - busy_timeout=5000:  wait up to 5s for a lock instead of returning
//     SQLITE_BUSY immediately
func buildDSN(path string) string {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	return "file:" + path + "?" + q.Encode()
}

//go:embed schema.sql
var ddl string

// Store wraps the sqlc Queries and owns the database connection.
type Store struct {
	db      *sql.DB
	queries *Queries
}

// Open opens (or creates) the SQLite database at path and applies the schema.
func Open(path string) (*Store, error) {
	sqldb, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(storeMaxOpenConns)
	sqldb.SetMaxIdleConns(storeMaxIdleConns)
	sqldb.SetConnMaxIdleTime(storeConnMaxIdleTime)
	if _, err = sqldb.Exec(ddl); err != nil {
		sqldb.Close()
		return nil, err
	}
	if err := migrate(sqldb); err != nil {
		sqldb.Close()
		return nil, err
	}
	return &Store{db: sqldb, queries: New(sqldb)}, nil
}

// migrate applies additive migrations for pre-existing databases.
// Each step is idempotent: detect column, add if missing.
func migrate(db *sql.DB) error {
	if has, err := hasColumn(db, "simulation_runs", "created_by"); err != nil {
		return err
	} else if !has {
		if _, err := db.Exec("ALTER TABLE simulation_runs ADD COLUMN created_by TEXT"); err != nil {
			return err
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping verifies the database connection is alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// SaveRun persists a simulation context and its result.
func (s *Store) SaveRun(ctx context.Context, simCtx simulator.SimContext, result *simulator.DecisionResult, user string) (SimulationRun, error) {
	ctxJSON, err := json.Marshal(simCtx)
	if err != nil {
		return SimulationRun{}, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return SimulationRun{}, err
	}

	var matchedRuleID, matchedRuleName *string
	if result.MatchedRule != nil {
		matchedRuleID = &result.MatchedRule.ID
		matchedRuleName = &result.MatchedRule.Name
	}

	var createdBy *string
	if user != "" {
		createdBy = &user
	}

	return s.queries.InsertSimulationRun(ctx, InsertSimulationRunParams{
		ContextJson:     string(ctxJSON),
		Action:          result.Action,
		MatchedRuleID:   matchedRuleID,
		MatchedRuleName: matchedRuleName,
		ResultJson:      string(resultJSON),
		CreatedBy:       createdBy,
	})
}

// ListRuns returns simulation runs ordered by most recent first.
func (s *Store) ListRuns(ctx context.Context, limit, offset int64) ([]SimulationRun, error) {
	return s.queries.ListSimulationRuns(ctx, ListSimulationRunsParams{
		Limit:  limit,
		Offset: offset,
	})
}

// GetRun fetches a single simulation run by ID.
func (s *Store) GetRun(ctx context.Context, id int64) (SimulationRun, error) {
	return s.queries.GetSimulationRun(ctx, id)
}

// DeleteRun removes a simulation run by ID.
func (s *Store) DeleteRun(ctx context.Context, id int64) error {
	return s.queries.DeleteSimulationRun(ctx, id)
}

// CountRuns returns the total number of stored simulation runs.
func (s *Store) CountRuns(ctx context.Context) (int64, error) {
	return s.queries.CountSimulationRuns(ctx)
}
