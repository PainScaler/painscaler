package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
)

var fileSink io.Writer = io.Discard

// Init configures the global slog default logger to write JSON to a rotated
// file plus errors to stderr. Returns the file sink so callers can close it
// on shutdown if needed (lumberjack also has its own Close).
func Init(cfg Config) error {
	if cfg.Dir != "" {
		if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
			return err
		}
	}

	lj := &lumberjack.Logger{
		Filename:   filepath.Join(cfg.Dir, cfg.File),
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}
	fileSink = lj

	stderrHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	})
	fileHandler := slog.NewJSONHandler(lj, &slog.HandlerOptions{
		Level: cfg.Level,
	})

	mh := multiHandler{handlers: []slog.Handler{fileHandler, stderrHandler}}
	logger := slog.New(mh).With(
		slog.String("service", cfg.Service),
		slog.String("version", cfg.Version),
		slog.String("commit", cfg.Commit),
	)
	slog.SetDefault(logger)
	SetBuildInfo(cfg.Version, cfg.Commit, cfg.BuildDate)
	return nil
}

// WithRequestID returns a context carrying the request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// RequestIDFrom extracts a request ID from context, or "" if absent.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}

// multiHandler fans out a record to all handlers that accept its level.
type multiHandler struct{ handlers []slog.Handler }

func (m multiHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, lvl) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clones := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		clones[i] = h.WithAttrs(attrs)
	}
	return multiHandler{handlers: clones}
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	clones := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		clones[i] = h.WithGroup(name)
	}
	return multiHandler{handlers: clones}
}
