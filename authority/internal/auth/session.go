package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Session struct {
	ID           string
	SubscriberID string
	ExpiresAt    time.Time
}

func CreateSession(ctx context.Context, pool *pgxpool.Pool, subscriberID string) (string, error) {
	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO sessions (subscriber_id, expires_at)
		 VALUES ($1, NOW() + INTERVAL '8 hours')
		 RETURNING id`,
		subscriberID,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

func GetSession(ctx context.Context, pool *pgxpool.Pool, sessionID string) (*Session, error) {
	s := &Session{}
	err := pool.QueryRow(ctx,
		`SELECT id, subscriber_id, expires_at
		 FROM sessions
		 WHERE id = $1 AND expires_at > NOW()`,
		sessionID,
	).Scan(&s.ID, &s.SubscriberID, &s.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func DeleteSession(ctx context.Context, pool *pgxpool.Pool, sessionID string) error {
	_, err := pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	return err
}

func CleanExpiredSessions(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
