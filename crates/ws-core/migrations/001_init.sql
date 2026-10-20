-- 001_init: initial Wardstone schema — tenants, certificate authorities,
-- and issued-serial bookkeeping.
--
-- `used_serials` is created here (not in a later migration) so Plan 2 does not
-- renumber migrations; it is consumed by Task 8 when CA issuance records the
-- serials it hands out.
--
-- Note: Postgres 16 provides gen_random_uuid() built in — no pgcrypto needed.

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Table name for CA rows is `cas` (avoiding clashes with reserved words).
CREATE TABLE cas (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    subject text NOT NULL,
    is_root boolean NOT NULL,
    parent_id uuid REFERENCES cas(id),
    key_type text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    cert_pem text NOT NULL,
    key_file text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE used_serials (
    ca_id uuid REFERENCES cas(id),
    serial bigint NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ca_id, serial)
);