-- Published registry documents, stored so that every client fetching in the
-- same hour gets byte-identical output.
--
-- Holding the document only in memory would break in two ways. An authority
-- restart inside an hour would rebuild and could produce different bytes under
-- the same version, which a client that saw both would correctly report as
-- equivocation that never happened. And an in-memory version counter resets on
-- restart, after which clients would reject every new document as a rollback.
--
-- valid_after is UNIQUE so one hour has exactly one document. version is the
-- primary key and strictly increases, which is what the client's rollback rule
-- compares against.
CREATE TABLE registry_documents (
    version     BIGINT      PRIMARY KEY,
    valid_after TIMESTAMPTZ NOT NULL UNIQUE,
    document    BYTEA       NOT NULL,
    signatures  JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE registry_documents
    ADD CONSTRAINT registry_documents_version_positive CHECK (version > 0),
    ADD CONSTRAINT registry_documents_document_nonempty CHECK (octet_length(document) > 0);

-- The serving path looks a document up by its hour on every request.
CREATE INDEX registry_documents_valid_after_idx ON registry_documents (valid_after DESC);
