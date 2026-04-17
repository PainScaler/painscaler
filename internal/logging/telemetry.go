package logging

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const MaxBatchSize = 100

type TelemetryEvent struct {
	Type         string    `json:"type"`
	TS           time.Time `json:"ts"`
	Route        string    `json:"route,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
	ErrorStack   string    `json:"error_stack,omitempty"`
}

type TelemetryBatch struct {
	Events []TelemetryEvent `json:"events"`
}

// RecordTelemetryBatch validates a frontend telemetry batch, emits one
// structured log line per event, and updates the prom counter.
func RecordTelemetryBatch(ctx context.Context, user string, batch TelemetryBatch) error {
	if len(batch.Events) > MaxBatchSize {
		return errors.New("telemetry batch too large")
	}
	for _, e := range batch.Events {
		if e.Type == "" {
			continue
		}
		FrontendEventsTotal.WithLabelValues(e.Type).Inc()
		attrs := []slog.Attr{
			slog.String("source", "frontend"),
			slog.String("type", e.Type),
			slog.String("user", user),
			slog.String("request_id", RequestIDFrom(ctx)),
		}
		if !e.TS.IsZero() {
			attrs = append(attrs, slog.Time("event_ts", e.TS))
		}
		if e.Route != "" {
			attrs = append(attrs, slog.String("route", e.Route))
		}
		if e.ErrorMessage != "" {
			attrs = append(attrs, slog.String("error_message", e.ErrorMessage))
		}
		if e.ErrorStack != "" {
			attrs = append(attrs, slog.String("error_stack", e.ErrorStack))
		}
		level := slog.LevelInfo
		if e.Type == "error" {
			level = slog.LevelWarn
		}
		slog.LogAttrs(ctx, level, "frontend event", attrs...)
	}
	return nil
}
