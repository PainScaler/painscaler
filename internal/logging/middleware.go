package logging

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	HeaderRequestID = "X-Request-Id"
	MetricsPath     = "/metrics"
)

// RequestID assigns a UUID to every request, exposes it on the response,
// and stashes it in the request context for downstream handlers.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(HeaderRequestID)
		if id == "" {
			id = uuid.NewString()
		}
		c.Writer.Header().Set(HeaderRequestID, id)
		c.Set("request_id", id)
		c.Request = c.Request.WithContext(WithRequestID(c.Request.Context(), id))
		c.Next()
	}
}

// AccessLog emits one structured log line per request and updates the prom
// counter + histogram. Skips MetricsPath to avoid scrape noise.
func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == MetricsPath {
			c.Next()
			return
		}
		start := time.Now()
		c.Next()
		dur := time.Since(start)

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		status := c.Writer.Status()
		statusStr := strconv.Itoa(status)

		HTTPRequestsTotal.WithLabelValues(route, c.Request.Method, statusStr).Inc()
		HTTPRequestDurationSeconds.WithLabelValues(route, c.Request.Method).Observe(dur.Seconds())

		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}

		attrs := []slog.Attr{
			slog.String("request_id", RequestIDFrom(c.Request.Context())),
			slog.String("route", route),
			slog.String("method", c.Request.Method),
			slog.Int("status", status),
			slog.Int64("duration_ms", dur.Milliseconds()),
			slog.Int("bytes_out", c.Writer.Size()),
			slog.String("client_ip", c.ClientIP()),
			slog.String("user_agent", c.Request.UserAgent()),
		}
		if user := c.GetHeader("Remote-User"); user != "" {
			attrs = append(attrs, slog.String("user", user))
		}
		if errs := c.Errors.String(); errs != "" {
			attrs = append(attrs, slog.String("errors", errs))
		}
		slog.LogAttrs(c.Request.Context(), level, "http request", attrs...)
	}
}
