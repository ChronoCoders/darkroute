-- Tracks per-issuance timestamps so the operator dashboard can show a
-- list of recent token issuances. SECURITY_MODEL §5.2 step 8 forbids
-- storing token values; only the timestamp + subscriber id is persisted.
CREATE TABLE token_issuance_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id UUID NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX token_issuance_events_subscriber_id_issued_at_idx
    ON token_issuance_events (subscriber_id, issued_at DESC);
