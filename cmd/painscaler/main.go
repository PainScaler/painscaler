package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/painscaler/painscaler/internal/fetcher"
	"github.com/painscaler/painscaler/internal/logging"
	"github.com/painscaler/painscaler/internal/server"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logCfg := logging.ConfigFromEnv()
	logCfg.Version = version
	logCfg.Commit = commit
	logCfg.BuildDate = date
	if err := logging.Init(logCfg); err != nil {
		slog.Error("logging init failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("starting painscaler",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.String("log_dir", logCfg.Dir),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if path := fetcher.DemoSeedPath(); path != "" {
		if err := fetcher.SeedDemoCache(path); err != nil {
			slog.Error("seed demo cache", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	srv, err := server.New(server.About{
		Version: version,
		Commit:  commit,
		Date:    date,
		Demo:    fetcher.DemoSeedPath() != "",
	})
	if err != nil {
		slog.Error("init server", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer srv.Close()

	if err := srv.Run(ctx, ":8080"); err != nil {
		slog.Error("server stopped", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
