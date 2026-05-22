CREATE TABLE circuit_assignments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_id UUID NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
    guard_id      UUID NOT NULL REFERENCES relay_nodes(id),
    middle_id     UUID NOT NULL REFERENCES relay_nodes(id),
    exit_id       UUID NOT NULL REFERENCES relay_nodes(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX circuit_assignments_subscriber_id_created_at_idx
    ON circuit_assignments (subscriber_id, created_at DESC);
