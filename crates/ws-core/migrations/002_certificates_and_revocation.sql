-- 002: issued-certificate records and CRL bookkeeping.
--
-- `certificates` holds one row per issued leaf, keyed per-issuer by
-- (ca_id, serial) (RFC 5280 section 4.1.2.2 per-issuer serial uniqueness),
-- with revocation state inline: revocation is an UPDATE guarded by
-- `status='active'`, so a double revoke is structurally idempotent (the
-- second call updates zero rows). The SAN arrays keep DNS/IP identities
-- queryable for renewal workflows; `serial_hex` is the lowercase-hex form
-- tools and humans read. The two indexes serve the tenant listing
-- (expiry order) and the status-scanned queries (expiry monitor, CRL
-- building).
--
-- `crls` holds each emitted CRL for a CA (rows are written by Task 9's
-- publisher; the table lands here so all of Task 7's schema arrives in
-- one migration).

CREATE TABLE certificates (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    ca_id uuid NOT NULL REFERENCES cas(id),
    profile_name text NOT NULL,
    subject text NOT NULL,
    serial bigint NOT NULL,
    serial_hex text NOT NULL,
    san_dns text[] NOT NULL DEFAULT '{}',
    san_ips inet[] NOT NULL DEFAULT '{}',
    key_type text NOT NULL,
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    cert_pem text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    revoked_at timestamptz NULL,
    revocation_reason text NULL,
    source text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (ca_id, serial)
);

CREATE INDEX certificates_tenant_not_after ON certificates (tenant_id, not_after);
CREATE INDEX certificates_tenant_status ON certificates (tenant_id, status);

CREATE TABLE crls (
    id uuid PRIMARY KEY,
    ca_id uuid NOT NULL REFERENCES cas(id),
    issued_at timestamptz NOT NULL,
    next_update timestamptz NOT NULL,
    crl_pem text NOT NULL,
    UNIQUE (ca_id, issued_at)
);
