-- Published registry documents, stored so that every client fetching in the
-- same hour gets byte-identical output.
--
-- Holding the document only in memory would break in two ways. An authority
-- restart inside an hour would rebuild and could produce different bytes under
-- the same version, which a client that saw both would correctly report as
-- equivocation that never happened. And an in-memory version counter resets on
-- restart, after which clients would reject every new document as a rollback.
--
-- valid_after is UNIQUE so one hour has exactly one document.
--
-- version is derived from valid_after rather than counted. With MAX(version)+1,
-- two instances whose clocks differ by a few minutes could publish out of
-- order: a slow instance publishing an earlier hour after a fast one published
-- a later hour would give the older document the higher version, and a client
-- would accept it as newer. Two instances computing the same MAX+1 also collide
-- on the primary key and fail transiently. Hours since the epoch makes version
-- order and hour order the same thing, with no query and no race.
CREATE TABLE registry_documents (
    version     BIGINT      PRIMARY KEY,
    valid_after TIMESTAMPTZ NOT NULL UNIQUE,
    document    BYTEA       NOT NULL,
    signatures  JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE registry_documents
    ADD CONSTRAINT registry_documents_version_positive CHECK (version > 0),
    ADD CONSTRAINT registry_documents_document_nonempty CHECK (octet_length(document) > 0),
    -- Publication is hourly, so an off-hour valid_after is a bug in the
    -- publisher rather than a value to store.
    ADD CONSTRAINT registry_documents_valid_after_on_hour
        CHECK (valid_after = date_trunc('hour', valid_after)),
    -- The database holds the publisher to the derivation, so a future change
    -- that reintroduced a counter would fail here rather than ship.
    ADD CONSTRAINT registry_documents_version_is_hour
        CHECK (version = floor(extract(epoch from valid_after) / 3600)::bigint);

-- The serving path looks a document up by its hour on every request.
CREATE INDEX registry_documents_valid_after_idx ON registry_documents (valid_after DESC);
