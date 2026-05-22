package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Health(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := "ok"
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			status = "degraded"
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":    status,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}
}
