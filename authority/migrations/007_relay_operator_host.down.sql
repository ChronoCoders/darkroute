DROP INDEX IF EXISTS relay_nodes_host_id_idx;
DROP INDEX IF EXISTS relay_nodes_operator_id_idx;

ALTER TABLE relay_nodes
    DROP CONSTRAINT IF EXISTS relay_nodes_host_id_nonempty,
    DROP CONSTRAINT IF EXISTS relay_nodes_operator_id_nonempty;

ALTER TABLE relay_nodes
    DROP COLUMN IF EXISTS host_id,
    DROP COLUMN IF EXISTS operator_id;
