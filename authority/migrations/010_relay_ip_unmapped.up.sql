-- An IPv4-mapped IPv6 address names the same host as its IPv4 form, so storing
-- both spellings would put two names for one host into the signed registry.
-- Readers then compare them as different families, which skips the IPv4 prefix
-- rule in SECURITY_MODEL 5.3 and lets through a path that rule forbids.
--
-- ProvisionRelay unmaps before storing. This constraint holds the database to
-- that, so a future insert path that forgot fails here rather than shipping a
-- registry with two spellings in it.
--
-- 006 and 007 refuse to run against a non-empty relay_nodes, because the
-- columns they add cannot be filled for an existing row. This one narrows that:
-- a row can be checked directly, and a table of plain addresses is already
-- correct, so refusing it would block the migration for no reason. Only a
-- mapped row stops the migration, and it stops it rather than being rewritten,
-- because silently changing a stored address is the thing both of those
-- migrations exist to avoid.
DO $$
DECLARE
    offending integer;
BEGIN
    SELECT count(*) INTO offending FROM relay_nodes WHERE ip <<= '::ffff:0:0/96'::inet;
    IF offending > 0 THEN
        RAISE EXCEPTION 'relay_nodes holds % row(s) with an IPv4-mapped address: re-provision those relays so the registry carries one spelling', offending;
    END IF;
END
$$;

ALTER TABLE relay_nodes
    ADD CONSTRAINT relay_nodes_ip_not_mapped
        CHECK (NOT (ip <<= '::ffff:0:0/96'::inet));
