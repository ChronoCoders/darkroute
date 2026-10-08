-- Route assignment is removed: the client selects its own path from the signed
-- registry and the authority records nothing about it (SECURITY_MODEL 5.3,
-- docs/DECISIONS.md entry 5). Migration 004 created this table, and
-- ARCHITECTURE 7 says a later migration must drop it.
--
-- Every row is lost and the down migration cannot bring them back. That is the
-- intent rather than a side effect: these rows are exactly the record the
-- authority is supposed to stop keeping.
DROP INDEX IF EXISTS circuit_assignments_subscriber_id_created_at_idx;
DROP TABLE IF EXISTS circuit_assignments;
