-- Onboarding gate (Phase 5): new subscriptions must be reviewed before
-- their owner can request circuits or issue tokens. The default flips
-- from application-side 'active' to a database-level 'pending_review';
-- handlers/auth.go now uses the column default in the INSERT.
ALTER TABLE subscriptions ALTER COLUMN status SET DEFAULT 'pending_review';
