package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dslabs/darkroute/authority/internal/auth"
)

type AuthHandler struct {
	pool *pgxpool.Pool
	jm   *auth.JWTManager
	rl   *rateLimiter
}

func NewAuthHandler(pool *pgxpool.Pool, jm *auth.JWTManager) *AuthHandler {
	return &AuthHandler{
		pool: pool,
		jm:   jm,
		rl:   newRateLimiter(5, 5*time.Minute),
	}
}

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (r *rateLimiter) check(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-r.window)
	arr := r.attempts[ip]
	fresh := arr[:0]
	for _, t := range arr {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	r.attempts[ip] = fresh
	return len(fresh) < r.limit
}

func (r *rateLimiter) record(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts[ip] = append(r.attempts[ip], time.Now())
}

func clientIP(req *http.Request) string {
	if f := req.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	host := req.RemoteAddr
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	return host
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("response encode failed", "err", err)
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !h.rl.check(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}
	var req credentials
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	var id, hash, role string
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, password, role FROM subscribers WHERE email = $1`, req.Email,
	).Scan(&id, &hash, &role)
	if err != nil {
		h.rl.record(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	ok, err := auth.VerifyPassword(req.Password, hash)
	if err != nil || !ok {
		h.rl.record(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	var tier string
	err = h.pool.QueryRow(r.Context(),
		`SELECT tier FROM subscriptions WHERE subscriber_id = $1 ORDER BY created_at DESC LIMIT 1`, id,
	).Scan(&tier)
	if err != nil {
		tier = "free"
	}
	sessID, err := auth.CreateSession(r.Context(), h.pool, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	tok, err := h.jm.GenerateToken(id, role, tier)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessID,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		Expires:  time.Now().Add(8 * time.Hour),
	})
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_id"); err == nil {
		if err := auth.DeleteSession(r.Context(), h.pool, cookie.Value); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req credentials
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		return
	}
	if len(req.Password) < 16 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password_too_short"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	var id string
	err = h.pool.QueryRow(r.Context(),
		`INSERT INTO subscribers (email, password) VALUES ($1, $2) RETURNING id`,
		req.Email, hash,
	).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "email_exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO subscriptions (subscriber_id, tier, status, current_period_start, current_period_end)
		 VALUES ($1, 'free', 'active', NOW(), NOW() + INTERVAL '30 days')`,
		id,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
