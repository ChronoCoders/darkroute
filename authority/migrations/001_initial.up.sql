CREATE TABLE subscribers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'operator',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id UUID NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE subscriptions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id        UUID NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
    tier                 TEXT NOT NULL,
    status               TEXT NOT NULL,
    tokens_issued        BIGINT NOT NULL DEFAULT 0,
    bandwidth_used       BIGINT NOT NULL DEFAULT 0,
    current_period_start TIMESTAMPTZ NOT NULL,
    current_period_end   TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE relay_nodes (
    id             UUID PRIMARY KEY,
    api_key_hash   TEXT NOT NULL,
    endpoint       TEXT NOT NULL,
    region         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'inactive',
    last_heartbeat TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX sessions_subscriber_id_idx ON sessions (subscriber_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX subscriptions_subscriber_id_idx ON subscriptions (subscriber_id);
CREATE INDEX relay_nodes_status_idx ON relay_nodes (status);
CREATE INDEX relay_nodes_last_heartbeat_idx ON relay_nodes (last_heartbeat);
