-- 004: stored OCSP responses.
--
-- One row per OCSP response the CA published for one of its
-- certificates: the RFC 6960 response bytes are kept verbatim in
-- `resp_der` (a signed artifact is stored, never re-derived), the status
-- the response reports is kept alongside them as text, and the validity
-- window the response was published under is kept as `this_update` /
-- `next_update`. `get_latest` serves the most recently published answer
-- for a (ca_id, serial) pair, which is the answer a client should be
-- given.
--
-- The `UNIQUE (ca_id, serial, this_update)` key makes republishing the
-- same response for the same instant a typed duplicate instead of a
-- silent overwrite.

CREATE TABLE ocsp_responses (
    id uuid PRIMARY KEY,
    ca_id uuid NOT NULL REFERENCES cas(id),
    serial bigint NOT NULL,
    status text NOT NULL,
    this_update timestamptz NOT NULL,
    next_update timestamptz NOT NULL,
    resp_der bytea NOT NULL,
    UNIQUE (ca_id, serial, this_update)
);

CREATE INDEX ocsp_responses_ca_serial ON ocsp_responses (ca_id, serial);
