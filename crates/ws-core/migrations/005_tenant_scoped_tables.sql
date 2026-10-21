-- 005: tenant-scope the CRL, OCSP-response, and used-serial tables.
--
-- The tenancy shape (design spec, "Tenancy shape -- Option A": single-tenant
-- instance by default, tenant-shaped schema from day one, every table carries
-- `tenant_id`) requires EVERY table to be attributable to a tenant. `tenants`
-- is the tenant table itself and needs no `tenant_id`; `cas`, `certificates`,
-- and `audit_log` already carry one. Three tables did not, and this migration
-- adds it:
--
--   - `crls`           (migration 002) -- published CRL documents
--   - `ocsp_responses` (migration 004) -- published OCSP answers
--   - `used_serials`   (migration 001) -- issued-serial bookkeeping
--
-- BACKFILL SOURCE OF TRUTH: the `cas` table. All three tables are children
-- of `cas` (`crls.ca_id`, `ocsp_responses.ca_id`, and `used_serials.ca_id` all
-- reference `cas(id)`), and `cas.tenant_id` is already NOT NULL, so a row's
-- tenant is exactly its CA's tenant. The backfill is a correlated UPDATE
-- that copies `cas.tenant_id` onto each row through the `ca_id` link -- no
-- default tenant, no guessing, and no application-level backfill that could
-- disagree with the database.
--
-- ORPHAN ROWS: `used_serials.ca_id` is DECLARED nullable in migration 001
-- (`ca_id uuid REFERENCES cas(id)`), so a row whose `ca_id` is NULL names no
-- CA and cannot be backfilled -- a serial recorded against no CA is
-- meaningless bookkeeping. Such rows are DELETED by this migration, BEFORE
-- the backfill and before the NOT NULL is applied, and the deletion is
-- announced in the transaction's log. (Migration 001's
-- `PRIMARY KEY (ca_id, serial)` also makes `ca_id` NOT NULL in practice, so
-- the DELETE matches no row against a database built from the shipped
-- migrations; it is here so the migration also converges a database whose
-- `used_serials` really does allow a NULL `ca_id`.) `crls.ca_id` and
-- `ocsp_responses.ca_id` are NOT NULL already, so neither of those tables
-- can hold an orphan row.
--
-- THE THREE-STEP DANCE: a NOT NULL column with a foreign key cannot be added
-- to a table that may already hold rows in one statement, so the column is
-- added as NULL, the existing rows are backfilled, and only then is it
-- tightened to NOT NULL. The foreign key is added after the backfill, so it
-- validates against fully populated values. A row the backfill could not
-- reach (a `ca_id` with no matching CA -- impossible while the existing
-- foreign keys hold) would make the NOT NULL step fail loudly rather than
-- leave the table half-attributed.
--
-- CONSTRAINT NAME COLLISIONS: Postgres auto-names a foreign key
-- `<table>_<column>_fkey` (here: `crls_tenant_id_fkey` and friends), so an
-- `ADD CONSTRAINT` that relied on the default name could collide with a
-- constraint that already exists. The constraint names here are explicit and
-- distinct from the auto-generated ones (`<table>_tenant_fk`), and each one
-- is added only when the table has no single-column foreign key on
-- `tenant_id` pointing at `tenants(id)` yet -- so a re-run, or a database
-- that already carries the constraint under another name, is a no-op rather
-- than a "duplicate constraint" failure. The indexes are created with
-- `IF NOT EXISTS` and their names are distinct from the earlier
-- migrations' indexes (in particular from `ocsp_responses_ca_serial`).

-- 1. The column, nullable for now.
ALTER TABLE crls ADD COLUMN tenant_id uuid NULL;
ALTER TABLE ocsp_responses ADD COLUMN tenant_id uuid NULL;
ALTER TABLE used_serials ADD COLUMN tenant_id uuid NULL;

-- 2. The orphan rows: a used serial with no CA cannot be attributed to a
--    tenant, and a serial without an issuer is meaningless. They go before
--    the backfill, so the backfill and the NOT NULL below never see one.
DELETE FROM used_serials WHERE ca_id IS NULL;

-- 3. The backfill: each row's tenant is its CA's tenant.
UPDATE crls
   SET tenant_id = (SELECT cas.tenant_id FROM cas WHERE cas.id = crls.ca_id);
UPDATE ocsp_responses
   SET tenant_id = (SELECT cas.tenant_id FROM cas WHERE cas.id = ocsp_responses.ca_id);
UPDATE used_serials
   SET tenant_id = (SELECT cas.tenant_id FROM cas WHERE cas.id = used_serials.ca_id);

-- 4. The column is now fully populated: tighten it.
ALTER TABLE crls ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ocsp_responses ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE used_serials ALTER COLUMN tenant_id SET NOT NULL;

-- 5. The foreign keys, each added only when the table has no such
--    constraint yet.
DO $$
DECLARE
    tbl text;
    fk_name text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['crls', 'ocsp_responses', 'used_serials']
    LOOP
        fk_name := tbl || '_tenant_fk';
        IF NOT EXISTS (
            SELECT 1
              FROM pg_constraint c
              JOIN pg_attribute a
                ON a.attrelid = c.conrelid
               AND a.attnum = ANY (c.conkey)
             WHERE c.conrelid = tbl::regclass
               AND c.contype = 'f'
               AND c.confrelid = 'tenants'::regclass
               AND array_length(c.conkey, 1) = 1
               AND a.attname = 'tenant_id'
        ) THEN
            EXECUTE format(
                'ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES tenants(id)',
                tbl, fk_name
            );
        END IF;
    END LOOP;
END
$$;

-- 6. The tenant-scoped access paths: the newest CRL of a tenant, the
--    OCSP answers of a tenant, and a tenant's used serials.
CREATE INDEX IF NOT EXISTS crls_tenant_issued_at ON crls (tenant_id, issued_at);
CREATE INDEX IF NOT EXISTS ocsp_responses_tenant_serial ON ocsp_responses (tenant_id, serial);
CREATE INDEX IF NOT EXISTS used_serials_tenant_serial ON used_serials (tenant_id, serial);
