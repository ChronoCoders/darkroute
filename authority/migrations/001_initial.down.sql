DROP INDEX IF EXISTS relay_nodes_last_heartbeat_idx;
DROP INDEX IF EXISTS relay_nodes_status_idx;
DROP INDEX IF EXISTS subscriptions_subscriber_id_idx;
DROP INDEX IF EXISTS sessions_expires_at_idx;
DROP INDEX IF EXISTS sessions_subscriber_id_idx;

DROP TABLE IF EXISTS relay_nodes;
DROP TABLE IF EXISTS subscriptions;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS subscribers;
