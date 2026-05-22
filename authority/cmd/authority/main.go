package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/auth"
	"github.com/dslabs/darkroute/authority/internal/blind"
	"github.com/dslabs/darkroute/authority/internal/config"
	"github.com/dslabs/darkroute/authority/internal/db"
	"github.com/dslabs/darkroute/authority/internal/handlers"
	"github.com/dslabs/darkroute/authority/internal/relay"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config validation failed: %v\n", err)
		os.Exit(1)
	}

	if err := db.RunMigrations(cfg.DatabaseURL); err != nil {
		slog.Error("migration failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	database, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	signer, err := blind.LoadOrGenerate(cfg.RSAKeyPath)
	if err != nil {
		slog.Error("rsa key load/generate failed", "err", err, "path", cfg.RSAKeyPath)
		os.Exit(1)
	}
	slog.Info("rsa signing key ready", "path", cfg.RSAKeyPath, "modulus_bits", blind.RSAKeySize)

	jm := auth.NewJWTManager(cfg.JWTSecret)
	ah := handlers.NewAuthHandler(database.Pool, jm)
	rh := handlers.NewRelayHandler(database.Pool, cfg.RelayAPIKeySalt, cfg.AllowedRelayIPs)
	th := handlers.NewTokenHandler(database.Pool, signer)

	r := chi.NewRouter()
	r.Get("/health", handlers.Health(database.Pool))

	r.Group(func(r chi.Router) {
		r.Use(handlers.RequestID, handlers.Logger)
		r.Get("/api/v1/authority/pubkey", th.HandlePubkey)
		r.Post("/api/v1/auth/register", ah.Register)
		r.Post("/api/v1/auth/login", ah.Login)
		r.Post("/api/v1/relay/heartbeat", rh.HandleRelayHeartbeat)
		r.Group(func(r chi.Router) {
			r.Use(handlers.Authenticate(jm, database.Pool))
			r.Post("/api/v1/auth/logout", ah.Logout)
			r.Post("/api/v1/tokens/issue", th.HandleIssue)
			r.Post("/api/v1/admin/relays/provision", rh.HandleProvisionRelay)
			r.Get("/api/v1/admin/relays", rh.HandleListRelays)
		})
	})

	var bgWG sync.WaitGroup
	bgWG.Add(2)
	go runSessionCleanup(ctx, &bgWG, database.Pool)
	go runRelayHealthSweep(ctx, &bgWG, database.Pool)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("server starting", "port", cfg.Port, "environment", cfg.Environment)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		slog.Info("shutdown requested", "signal", s.String())
	case err := <-serverErr:
		slog.Error("server error", "err", err)
	}

	shutdownCtx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
	cancel()
	bgWG.Wait()
	slog.Info("shutdown complete")
}

func runSessionCleanup(ctx context.Context, wg *sync.WaitGroup, pool *pgxpool.Pool) {
	defer wg.Done()
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			n, err := auth.CleanExpiredSessions(cctx, pool)
			cancel()
			if err != nil {
				slog.Error("session cleanup failed", "err", err)
				continue
			}
			slog.Info("session cleanup", "deleted", n)
		}
	}
}

func runRelayHealthSweep(ctx context.Context, wg *sync.WaitGroup, pool *pgxpool.Pool) {
	defer wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	const inactivityTTL = 90 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			n, err := relay.SweepInactiveRelays(cctx, pool, inactivityTTL)
			cancel()
			if err != nil {
				slog.Error("relay sweep failed", "err", err)
				continue
			}
			if n > 0 {
				slog.Info("relay sweep", "marked_inactive", n)
			}
		}
	}
}
