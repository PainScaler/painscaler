//go:generate go run ../../apigen/.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/painscaler/painscaler/internal/logging"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var authHeaders = []string{"Remote-User", "Remote-Email", "Remote-Groups", "Remote-Name"}

const (
	serverReadHeaderTimeout = 10 * time.Second
	serverReadTimeout       = 30 * time.Second
	serverWriteTimeout      = 120 * time.Second
	serverIdleTimeout       = 120 * time.Second
	shutdownGracePeriod     = 15 * time.Second
	maxRequestBodyBytes     = 1 << 20 // 1 MiB
)

// limitRequestBody caps incoming request payloads so that malformed or
// malicious clients cannot exhaust memory through large JSON bodies.
func limitRequestBody(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}

// Run starts the HTTP server and blocks until ctx is cancelled, then
// performs a graceful shutdown bounded by shutdownGracePeriod.
func (s *Server) Run(ctx context.Context, addr string) error {
	s.ctx = ctx

	router := gin.New()
	router.Use(gin.Recovery())

	trusted := parseTrusted(os.Getenv("TRUSTED_PROXIES"))
	if len(trusted) > 0 {
		_ = router.SetTrustedProxies(stringifyCIDRs(trusted))
	} else {
		router.SetTrustedProxies(nil)
	}

	router.Use(stripUntrustedAuthHeaders(trusted))
	router.Use(limitRequestBody(maxRequestBodyBytes))
	router.Use(logging.RequestID())
	router.Use(logging.AccessLog())

	router.GET(logging.MetricsPath, gin.WrapH(promhttp.Handler()))
	router.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.GET("/readyz", func(c *gin.Context) {
		if err := s.readyCheck(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})

	s.StartIndexWarmer(ctx)

	RegisterRoutes(router, s)

	srv := &http.Server{
		Addr:              addr,
		Handler:           router.Handler(),
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutdown requested", slog.String("reason", ctx.Err().Error()))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("graceful shutdown failed", slog.String("error", err.Error()))
			return err
		}
		return nil
	}
}

// stripUntrustedAuthHeaders deletes proxy-injected identity headers unless
// the request came from a trusted peer. Prevents direct callers from spoofing.
func stripUntrustedAuthHeaders(trusted []*net.IPNet) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !peerInCIDRs(c.RemoteIP(), trusted) {
			for _, h := range authHeaders {
				c.Request.Header.Del(h)
			}
		}
		c.Next()
	}
}

func parseTrusted(env string) []*net.IPNet {
	var nets []*net.IPNet
	for _, p := range strings.Split(env, ",") {
		t := strings.TrimSpace(p)
		if t == "" {
			continue
		}
		if !strings.Contains(t, "/") {
			if ip := net.ParseIP(t); ip != nil {
				if ip.To4() != nil {
					t += "/32"
				} else {
					t += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(t); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func peerInCIDRs(peer string, nets []*net.IPNet) bool {
	if peer == "" || len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func stringifyCIDRs(nets []*net.IPNet) []string {
	out := make([]string, len(nets))
	for i, n := range nets {
		out[i] = n.String()
	}
	return out
}
