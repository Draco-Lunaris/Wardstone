-- 006: enforce tenant/CA consistency with a composite foreign key.
--
-- THE INVARIANT: every child of `cas` -- `certificates`, `crls`,
-- `ocsp_responses`, and `used_serials` -- carries a `tenant_id` that is a
-- DENORMALIZED copy of its CA's tenant. Nothing in the schema enforced that
-- the copy was correct: a row could name a `tenant_id` different from the
-- tenant of the CA it points at. That is a silent cross-tenant leak, because
-- `CertificateRepo::list_by_tenant` filters on `certificates.tenant_id`, so a
-- drifted row would show up in another tenant's listing.
--
-- Migration 005 backfilled every existing row from `cas.tenant_id`, so every
-- row in a migrated database is already consistent and the foreign keys below
-- validate against the existing rows without `NOT VALID`. No data migration
-- is needed here.
--
-- THE UNIQUE CONSTRAINT IS A PREREQUISITE, NOT A DETAIL: a foreign key must
-- reference a column set that is the target of a unique constraint (or the
-- primary key). `cas.id` alone is the primary key, but the composite foreign
-- key below references the column set `(id, tenant_id)`, so that column set
-- needs its own unique constraint first. Postgres rejects a foreign key to a
-- non-unique column set ("there is no unique constraint matching given keys"),
-- which is why the `ALTER TABLE cas ADD CONSTRAINT ... UNIQUE (id, tenant_id)`
-- comes first. It is also the index the composite foreign key's lookups use.
--
-- `DEFERRABLE INITIALLY DEFERRED` IS LOAD-BEARING, NOT COSMETIC. The check
-- must not run at the end of each statement, because a CA may be moved
-- between tenants: the move updates `cas.tenant_id` and every child row's
-- `tenant_id` together. With an IMMEDIATE (checked-per-statement) foreign
-- key, the `UPDATE cas SET tenant_id = ...` is rejected on its own, before
-- the child rows have been updated -- "Key (id, tenant_id)=(...) is still
-- referenced from table crls" -- which would permanently forbid moving a CA
-- between tenants, with no way to order the updates so it works. A DEFERRED
-- check is postponed to the end of the transaction, so the move commits as
-- one transaction that updates `cas` and every child row together. The
-- constraint still bites: a mismatched-tenant row that is never reconciled
-- is rejected when the transaction commits.
--
-- THE COMPOSITE FOREIGN KEY IS ADDITIVE: the existing single-column
-- `tenant_id REFERENCES tenants(id)` foreign keys are KEPT. The composite
-- foreign key says "this (ca_id, tenant_id) pair names a CA" -- it says
-- nothing about whether the tenant itself exists. The single-column foreign
-- key is what says "this tenant exists"; the composite one says "and it is
-- the CA's tenant". Keeping both is what makes the pair of them equivalent
-- to "this row belongs to the CA's tenant, and that tenant is a real
-- tenant". Dropping the single-column foreign key would leave the tenant
-- column free to name a tenant that does not exist, and dropping the
-- composite one would leave it free to name the wrong tenant.

ALTER TABLE cas ADD CONSTRAINT cas_id_tenant_key UNIQUE (id, tenant_id);

ALTER TABLE certificates
    ADD CONSTRAINT certificates_ca_tenant_fk
    FOREIGN KEY (ca_id, tenant_id) REFERENCES cas (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE crls
    ADD CONSTRAINT crls_ca_tenant_fk
    FOREIGN KEY (ca_id, tenant_id) REFERENCES cas (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ocsp_responses
    ADD CONSTRAINT ocsp_responses_ca_tenant_fk
    FOREIGN KEY (ca_id, tenant_id) REFERENCES cas (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE used_serials
    ADD CONSTRAINT used_serials_ca_tenant_fk
    FOREIGN KEY (ca_id, tenant_id) REFERENCES cas (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;
