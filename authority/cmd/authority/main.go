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

	"github.com/ChronoCoders/quiethop/authority/internal/auth"
	"github.com/ChronoCoders/quiethop/authority/internal/blind"
	"github.com/ChronoCoders/quiethop/authority/internal/config"
	"github.com/ChronoCoders/quiethop/authority/internal/db"
	"github.com/ChronoCoders/quiethop/authority/internal/handlers"
	"github.com/ChronoCoders/quiethop/authority/internal/registry"
	"github.com/ChronoCoders/quiethop/authority/internal/relay"
)

// runRegistryKeygen writes a new registry signing key and prints only the
// public half, which the operator pins into clients. The seed is never printed
// and never logged.
func runRegistryKeygen(args []string) int {
	var path string
	switch {
	case len(args) == 1:
		path = args[0]
	case len(args) == 0:
		path = os.Getenv("REGISTRY_KEY_PATH")
	default:
		fmt.Fprintln(os.Stderr, "usage: authority registry-keygen [path]")
		return 2
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "registry-keygen needs a path argument or REGISTRY_KEY_PATH")
		return 2
	}
	pubHex, err := registry.GenerateKeyFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "registry-keygen failed: %v\n", err)
		return 1
	}
	fmt.Println(pubHex)
	return 0
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// `authority registry-keygen [path]` writes the registry signing key and
	// exits. It runs before config load because it needs none of it, and the
	// serving path must never generate a key (ARCHITECTURE 4.4).
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "registry-keygen" {
		os.Exit(runRegistryKeygen(args[1:]))
	}

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

	// Load only, never generate. A key invented here would sign a registry no
	// client has pinned, so every client would reject every document.
	regSigner, err := registry.LoadSigner(cfg.RegistryKeyPath)
	if err != nil {
		slog.Error("registry signing key load failed", "err", err, "path", cfg.RegistryKeyPath)
		os.Exit(1)
	}
	slog.Info("registry signing key ready",
		"path", cfg.RegistryKeyPath, "key_id", regSigner.KeyID())

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
	ch := handlers.NewCircuitHandler(database.Pool)
	acc := handlers.NewAccountHandler(database.Pool)
	adm := handlers.NewAdminHandler(database.Pool)
	reg := handlers.NewRegistryHandler(registry.NewPublisher(database.Pool, regSigner))

	r := chi.NewRouter()
	r.Get("/health", handlers.Health(database.Pool))

	r.Group(func(r chi.Router) {
		r.Use(handlers.RequestID, handlers.Logger)
		r.Get("/api/v1/authority/pubkey", th.HandlePubkey)
		// Public and unauthenticated: integrity comes from the signature,
		// and a session here would reveal who is about to build a circuit.
		r.Get("/api/v1/registry", reg.HandleRegistry)
		r.Post("/api/v1/auth/register", ah.Register)
		r.Post("/api/v1/auth/login", ah.Login)
		r.Post("/api/v1/relay/heartbeat", rh.HandleRelayHeartbeat)
		r.Group(func(r chi.Router) {
			r.Use(handlers.Authenticate(jm, database.Pool))
			r.Post("/api/v1/auth/logout", ah.Logout)
			r.Post("/api/v1/tokens/issue", th.HandleIssue)
			r.Get("/api/v1/tokens", th.HandleListTokens)
			r.Get("/api/v1/circuits/route", ch.HandleRoute)
			r.Get("/api/v1/circuits", ch.HandleListCircuits)
			r.Get("/api/v1/account", acc.HandleGetAccount)
			r.Get("/api/v1/usage", acc.HandleGetUsage)
			r.Group(func(r chi.Router) {
				r.Use(handlers.RequireRole("admin"))
				r.Post("/api/v1/admin/relays/provision", rh.HandleProvisionRelay)
				r.Get("/api/v1/admin/relays", rh.HandleListRelays)
				r.Get("/api/v1/admin/subscribers", adm.HandleListSubscribers)
				r.Post("/api/v1/admin/subscribers/{id}/approve", adm.HandleApproveSubscriber)
			})
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
