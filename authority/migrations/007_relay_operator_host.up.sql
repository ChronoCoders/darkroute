-- operator_id and host_id let the client check path diversity from the signed
-- registry alone (ARCHITECTURE 4.7, SECURITY_MODEL 5.3). Neither is declared by
-- the relay: the authority assigns both at provisioning, and a heartbeat never
-- touches them.
--
-- A row from before this migration has neither, and a relay without them cannot
-- appear in a registry a client is able to check. Rather than invent identifiers
-- or drop rows, this refuses to run against a non-empty table, as 006 does.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM relay_nodes) THEN
        RAISE EXCEPTION 'relay_nodes is not empty: re-provision every relay, because a row without operator_id and host_id cannot appear in the signed registry';
    END IF;
END
$$;

ALTER TABLE relay_nodes
    ADD COLUMN operator_id TEXT NOT NULL,
    ADD COLUMN host_id     TEXT NOT NULL;

ALTER TABLE relay_nodes
    ADD CONSTRAINT relay_nodes_operator_id_nonempty CHECK (length(operator_id) > 0),
    ADD CONSTRAINT relay_nodes_host_id_nonempty     CHECK (length(host_id) > 0);

CREATE INDEX relay_nodes_operator_id_idx ON relay_nodes (operator_id);
CREATE INDEX relay_nodes_host_id_idx     ON relay_nodes (host_id);
