-- 008: certificate profiles, the legacy-label backfill, and the CA
-- parent-tenant composite foreign key.
--
-- `profiles` (one per tenant) and `profile_revisions` (one per published
-- profile version; immutable once certificates reference it). The circular
-- reference -- a profile points at its current revision, a revision points
-- at its profile -- is cut the standard way: `profiles.current_revision_id`
-- starts NULL, and `profiles_current_revision_fk` is DEFERRABLE INITIALLY
-- DEFERRED, so creating a profile and its first revision in one
-- transaction (create profile, insert revision, point the profile at the
-- revision) commits atomically, while a commit that never set a revision
-- for a profile that has one is still rejected there.
--
-- THE LEGACY BACKFILL: `certificates.profile_name` (migration 002) is
-- `NOT NULL` and holds free-form labels matching no profile. The backfill
-- gives every pre-profile certificate a real revision to point at, per
-- tenant that owns certificates:
--
--   1. One `profiles` row named `legacy` per such tenant.
--   2. One `profile_revisions` row per DISTINCT label the tenant's
--      certificates carry, numbered 1, 2, 3... by label order (the
--      uniqueness constraint is `(profile_id, revision)`, so every legacy
--      revision needs its own number). The order is deterministic: the
--      same labels produce the same numbering on any run, and
--      `profiles.current_revision_id` points at the HIGHEST-numbered
--      revision.
--   3. Every certificate row is repointed at the revision matching its
--      label.
--
-- The revision rows carry explicit (not default) values for every NOT NULL
-- constraint column, so the row is complete and readable; `is_legacy =
-- true` marks the whole set as never-used-for-issuance. The constraint set
-- is the most permissive form because the schema has no per-tenant default
-- domain to read (a real default lives only in a profile's pattern list
-- and in the setup audit row): `key_type = 'rsa2048'`,
-- `key_usages = ARRAY['digital_signature','key_encipherment']`,
-- `eku = ARRAY['server_auth']`, `lifetime_days = 30`,
-- `san_patterns = ARRAY['*']`. `profile_revisions.actor_id` is
-- `TEXT NOT NULL` with no default, so the backfill supplies it explicitly:
-- `'system:migration-008'`.
--
-- `certificates.profile_name` is RETAINED as a denormalised label (display
-- only; the authority for a certificate's policy is
-- `profile_revision_id`). Dropping it needs a separate, later migration
-- after the code stops referencing it -- the plan's global constraint
-- forbids editing an applied migration.
--
-- STATEMENT ORDER IS LOAD-BEARING: `ALTER TABLE certificates ADD COLUMN
-- profile_revision_id` must precede the backfill UPDATE -- otherwise the
-- UPDATE has no column to write.
--
-- THE `cas` COMPOSITE FOREIGN KEY: a child CA's `(parent_id, tenant_id)`
-- must name `cas.(id, tenant_id)`, so a CA can never name a parent from
-- another tenant (the same invariant migration 006 enforced for
-- `certificates`/`crls`/`ocsp_responses`/`used_serials`, but for the CA
-- hierarchy itself). It is well-founded only because migration 006 added
-- `cas_id_tenant_key UNIQUE (id, tenant_id)` -- a foreign key must
-- reference a unique (or primary-key) column set. `DEFERRABLE INITIALLY
-- DEFERRED` for the same reason as 006: a CA may move between tenants
-- together with its children, and the pair of updates must commit as one
-- transaction. The single-column `parent_id REFERENCES cas(id)` from
-- migration 001 is KEPT: the composite FK says "(parent, tenant) names a
-- CA", the original says "the parent exists".
--
-- Only tenants that own certificates get a `legacy` profile: the backfill
-- exists so every existing certificate label resolves to a revision, and a
-- tenant with no certificates has nothing to resolve (no labels, and so --
-- per the shape above -- no revisions, leaving `current_revision_id`
-- dangling at NULL for a profile no certificate references).

CREATE TABLE profiles (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid NOT NULL REFERENCES tenants(id),
    name                TEXT NOT NULL,
    description         TEXT,
    current_revision_id uuid,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE profile_revisions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id    uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    revision      INTEGER NOT NULL,
    name          TEXT NOT NULL,
    key_type      TEXT NOT NULL,
    key_usages    TEXT[] NOT NULL,
    eku           TEXT[] NOT NULL,
    lifetime_days INTEGER NOT NULL,
    san_patterns  TEXT[] NOT NULL,
    is_legacy     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id      TEXT NOT NULL,
    UNIQUE (profile_id, revision)
);

ALTER TABLE profiles
    ADD CONSTRAINT profiles_current_revision_fk
    FOREIGN KEY (current_revision_id) REFERENCES profile_revisions(id) DEFERRABLE INITIALLY DEFERRED;

-- Before the backfill UPDATE: the column it writes must exist first.
ALTER TABLE certificates
    ADD COLUMN profile_revision_id uuid NULL REFERENCES profile_revisions(id);

ALTER TABLE cas
    ADD CONSTRAINT cas_parent_tenant_fk
    FOREIGN KEY (parent_id, tenant_id) REFERENCES cas (id, tenant_id) DEFERRABLE INITIALLY DEFERRED;

-- 1. One legacy profile per tenant that owns certificates. The table was
--    created empty above, so the conflict arm is belt and braces.
INSERT INTO profiles (tenant_id, name)
SELECT DISTINCT tenant_id, 'legacy'
  FROM certificates
ON CONFLICT (tenant_id, name) DO NOTHING;

-- 2. One legacy revision per distinct (tenant, label), numbered 1..N per
--    tenant in label order (deterministic), all bound to the tenant's
--    legacy profile.
INSERT INTO profile_revisions
    (profile_id, revision, name, key_type, key_usages, eku, lifetime_days,
     san_patterns, is_legacy, actor_id)
SELECT p.id,
       ROW_NUMBER() OVER (PARTITION BY c.tenant_id ORDER BY c.profile_name),
       c.profile_name,
       'rsa2048',
       ARRAY['digital_signature', 'key_encipherment'],
       ARRAY['server_auth'],
       30,
       ARRAY['*'],
       TRUE,
       'system:migration-008'
  FROM (SELECT DISTINCT tenant_id, profile_name FROM certificates) c
  JOIN profiles p ON p.tenant_id = c.tenant_id AND p.name = 'legacy';

-- 3. The profile's current revision is the highest-numbered legacy one.
UPDATE profiles p
   SET current_revision_id = r.id
  FROM profile_revisions r
 WHERE r.profile_id = p.id
   AND r.is_legacy
   AND r.revision = (SELECT max(r2.revision)
                       FROM profile_revisions r2
                      WHERE r2.profile_id = p.id);

-- 4. Repoint every certificate at the revision matching its label.
UPDATE certificates c
   SET profile_revision_id = r.id
  FROM profiles p
  JOIN profile_revisions r ON r.profile_id = p.id
 WHERE p.tenant_id = c.tenant_id
   AND p.name = 'legacy'
   AND r.name = c.profile_name;