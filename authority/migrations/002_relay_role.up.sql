ALTER TABLE relay_nodes ADD COLUMN role TEXT NOT NULL DEFAULT 'guard';
CREATE INDEX ON relay_nodes (role);
