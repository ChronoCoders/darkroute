-- Relays carry a long-term X25519 static public key (SECURITY_MODEL 5.10, 7.2)
-- and are addressed by an IP literal, so the client never resolves a name while
-- constructing a path. endpoint becomes tls_name and holds a hostname only,
-- used for SNI and certificate verification.
--
-- A relay row that predates this migration has no static key and cannot serve a
-- circuit under Noise NK. Rather than invent key material or drop rows, this
-- refuses to run against a non-empty table. Re-provision every relay instead.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM relay_nodes) THEN
        RAISE EXCEPTION 'relay_nodes is not empty: re-provision every relay, because a row without a static_pubkey cannot serve a circuit';
    END IF;
END
$$;

ALTER TABLE relay_nodes RENAME COLUMN endpoint TO tls_name;

ALTER TABLE relay_nodes
    ADD COLUMN static_pubkey BYTEA NOT NULL,
    ADD COLUMN ip            INET  NOT NULL,
    ADD COLUMN port          INTEGER NOT NULL;

ALTER TABLE relay_nodes
    ADD CONSTRAINT relay_nodes_static_pubkey_len CHECK (octet_length(static_pubkey) = 32),
    ADD CONSTRAINT relay_nodes_port_range        CHECK (port BETWEEN 1 AND 65535);
