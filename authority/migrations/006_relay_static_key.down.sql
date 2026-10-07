ALTER TABLE relay_nodes
    DROP CONSTRAINT IF EXISTS relay_nodes_port_range,
    DROP CONSTRAINT IF EXISTS relay_nodes_static_pubkey_len;

ALTER TABLE relay_nodes
    DROP COLUMN IF EXISTS port,
    DROP COLUMN IF EXISTS ip,
    DROP COLUMN IF EXISTS static_pubkey;

ALTER TABLE relay_nodes RENAME COLUMN tls_name TO endpoint;
