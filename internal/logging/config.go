package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Dir        string
	File       string
	Level      slog.Level
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
	Service    string
	Version    string
	Commit     string
	BuildDate  string
}

func ConfigFromEnv() Config {
	c := Config{
		Dir:        envOr("LOG_DIR", defaultLogDir()),
		File:       envOr("LOG_FILE", "painscaler.log"),
		Level:      parseLevel(os.Getenv("LOG_LEVEL")),
		MaxSizeMB:  envInt("LOG_MAX_SIZE_MB", 50),
		MaxBackups: envInt("LOG_MAX_BACKUPS", 10),
		MaxAgeDays: envInt("LOG_MAX_AGE_DAYS", 30),
		Compress:   envBool("LOG_COMPRESS", true),
		Service:    "painscaler",
	}
	return c
}

func defaultLogDir() string {
	if cfgDir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(cfgDir, "painscaler", "logs")
	}
	return "logs"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(os.Getenv(k))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
