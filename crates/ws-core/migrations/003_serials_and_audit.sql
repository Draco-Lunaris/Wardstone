-- 003: append-only audit log.
--
-- One row per security-relevant event (`ca_created`, `cert_issued`,
-- `cert_revoked`, `crl_built`, `key_generated`, ...). Append-only: the
-- repository surface deliberately exposes no UPDATE or DELETE — rows are
-- written once by `AuditRepo::record` and read by tenant-scoped paged
-- listings; nothing else may touch them. `created_at` is database-owned
-- (the `now()` default; `record` never binds a client timestamp), so an
-- entry cannot be backdated. `details` is a free-form JSON object for
-- structured context — ids and action labels only, never key material
-- (house rule: no secret bytes reach the database in plaintext form). The
-- `(tenant_id, created_at)` index serves `list_by_tenant`'s
-- newest-first paging.

CREATE TABLE audit_log (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_tenant_created_at ON audit_log (tenant_id, created_at);
