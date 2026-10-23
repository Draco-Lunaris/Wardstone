-- 011: the ACME (RFC 8555) persistence floor.
--
-- Four tenant-scoped tables back the ACME server:
--
--   acme_accounts       one row per JWK (identified by its RFC 7638
--                       thumbprint; the account URL resolves from it)
--   acme_orders         one row per certificate order
--   acme_authorizations one row per identifier validation; REUSED rows
--                       (order_id IS NULL) belong to the account and are
--                       shared across orders, order-scoped rows carry the
--                       order that demanded them
--   acme_challenges     one row per (authorization, challenge type); the
--                       client picks http-01 or dns-01
--
-- Every table carries `tenant_id` (`tenants.id`) -- the plan's tenancy
-- shape -- and every child also carries a COMPOSITE tenant-consistency
-- foreign key in migration 006's idiom, so a child can never name a parent
-- from another tenant:
--
--   acme_orders.account_id        + acme_orders.tenant_id
--        -> acme_accounts (id, tenant_id)
--   acme_authorizations.account_id + acme_authorizations.tenant_id
--        -> acme_accounts (id, tenant_id)
--   acme_challenges.authorization_id + acme_challenges.tenant_id
--        -> acme_authorizations (id, tenant_id)
--
-- THE UNIQUE CONSTRAINTS ARE PREREQUISITES, NOT DETAILS: a foreign key must
-- reference a column set that is the target of a unique constraint (or the
-- primary key). `acme_accounts.id` and `acme_authorizations.id` alone are
-- primary keys, but the composite foreign keys above reference the column
-- sets `(id, tenant_id)`, so those column sets need their own unique
-- constraints first (the same reason migration 006 added
-- `cas_id_tenant_key` before its children's foreign keys). Postgres rejects
-- a foreign key to a non-unique column set ("there is no unique constraint
-- matching given keys"). The uniques also serve as the composite foreign
-- keys' lookup indexes. `acme_challenges` needs no extra unique: its parent
-- `acme_authorizations` already carries one, which is WHY the authorization
-- table gets one even though nothing below references `acme_authorizations
-- (id, tenant_id)` besides it.
--
-- `DEFERRABLE INITIALLY DEFERRED` IS LOAD-BEARING, NOT COSMETIC: an ACME
-- order and its authorizations (and an authorization and its challenges)
-- mint together in ONE transaction -- the authz rows must exist before the
-- order row that references them can commit, and the challenges before the
-- authorization. Worse, the rows are interchangeable in either order: a
-- REUSED authorization is minted before the order it will be attached to
-- conceptually, while a NEW one is minted by the order that names it. An
-- IMMEDIATE (per-statement) check would reject any row whose parent lands
-- in the same transaction after it; a DEFERRED check is postponed to
-- COMMIT, so one transaction can insert the whole chain in any order. The
-- constraint still bites: a child that names a PARENT FROM ANOTHER TENANT
-- is rejected when the transaction commits -- the database refuses to
-- commit a cross-tenant link, which is precisely what the composite makes
-- unspeakable (the same property 006 gave the CA children).
--
-- THE COMPOSITE FOREIGN KEYS ARE ADDITIVE: the single-column
-- `tenant_id REFERENCES tenants(id)` foreign keys are KEPT (created with
-- the tables here). The composite says "this (account_id, tenant_id) pair
-- names an account"; the single-column one says "this tenant exists";
-- keeping both is what makes the pair of them equivalent to "this row
-- belongs to its referenced parent's tenant, and that tenant is real".
--
-- EVERY `status` COLUMN IS NOT NULL: each one decodes into its
-- `ws_core::models::acme` enum on read, so a NULL would be an unreadable
-- row. The CHECK constraints are the database backstop behind the enums'
-- FromStr parsers -- the two vocabularies must not drift (the schema-test
-- suite rejects an unknown value through each one).
--
-- `acme_accounts.status` DEFAULTs to 'valid': ACME accounts created through
-- the agreed-TOS (or no-TOS) flow are immediately usable, and the routes
-- pass the status explicitly on insert anyway (the default is schema
-- documentation of the flow's common case).
-- `acme_authorizations.status` and `acme_challenges.status` DEFAULT to
-- 'pending' for the same reason: a freshly minted validation challenge is
-- pending until proven otherwise. `acme_orders.status` has NO default --
-- an order is always born 'pending' AND the application always names it;
-- a forgotten name should be a loud bug, not a silent default.
--
-- SERVICE INDEXES: the tenant-scoped access paths the repositories read --
-- an account's orders newest-first, an account's authorization lookups per
-- identifier (the reuse-window query), and an authorization's challenges.
-- The `(tenant_id, account_id)` uniques are NOT enough for the order
-- listing because the created_at/id tiebreak ordering must not be a
-- post-filter sort of the tenant's whole order set.

CREATE TABLE acme_accounts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES tenants(id),
    jwk_thumbprint  TEXT NOT NULL,
    jwk             jsonb NOT NULL,
    status          TEXT NOT NULL
                    CHECK (status IN ('pending', 'valid', 'deactivated'))
                    DEFAULT 'valid',
    tos_agreed_at   TIMESTAMPTZ,
    contact         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, jwk_thumbprint)
);

CREATE TABLE acme_orders (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants(id),
    account_id     uuid NOT NULL REFERENCES acme_accounts(id),
    status         TEXT NOT NULL
                   CHECK (status IN ('pending', 'ready', 'processing',
                                     'valid', 'invalid')),
    profile_name   TEXT NOT NULL,
    identifiers    jsonb NOT NULL,
    csr_pem        TEXT,
    not_before     TIMESTAMPTZ,
    not_after      TIMESTAMPTZ,
    certificate_id uuid REFERENCES certificates(id),
    error          TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE acme_authorizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    account_id  uuid NOT NULL REFERENCES acme_accounts(id),
    identifier  TEXT NOT NULL,
    status      TEXT NOT NULL
                CHECK (status IN ('pending', 'valid', 'invalid', 'expired',
                                  'deactivated'))
                DEFAULT 'pending',
    expires_at  TIMESTAMPTZ NOT NULL,
    reused_from uuid REFERENCES acme_authorizations(id),
    order_id    uuid REFERENCES acme_orders(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id)
);

CREATE TABLE acme_challenges (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants(id),
    authorization_id uuid NOT NULL REFERENCES acme_authorizations(id),
    challenge_type   TEXT NOT NULL
                     CHECK (challenge_type IN ('http-01', 'dns-01')),
    token            TEXT NOT NULL,
    status           TEXT NOT NULL
                     CHECK (status IN ('pending', 'processing', 'valid',
                                       'invalid'))
                     DEFAULT 'pending',
    validated_at     TIMESTAMPTZ,
    error            TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The composite foreign keys' prerequisite unique constraints (see the
-- comment above): same shape and naming as 006's `cas_id_tenant_key`.
-- `acme_accounts` needs it for both the order and the authorization
-- children; `acme_authorizations` for the challenges.
ALTER TABLE acme_accounts
    ADD CONSTRAINT acme_accounts_id_tenant_key UNIQUE (id, tenant_id);

-- (acme_authorizations already gained UNIQUE (id, tenant_id) inline above;
-- written again here would be a duplicate-constraint error. The constraint
-- is listed with its siblings in the comment block.)

-- One composite, tenant-consistency foreign key per child, 006's idiom
-- verbatim (the names are pinned: the schema-test suite asserts them).
ALTER TABLE acme_orders
    ADD CONSTRAINT acme_orders_account_tenant_fk
    FOREIGN KEY (account_id, tenant_id) REFERENCES acme_accounts (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE acme_authorizations
    ADD CONSTRAINT acme_authorizations_account_tenant_fk
    FOREIGN KEY (account_id, tenant_id) REFERENCES acme_accounts (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE acme_challenges
    ADD CONSTRAINT acme_challenges_authorization_tenant_fk
    FOREIGN KEY (authorization_id, tenant_id)
    REFERENCES acme_authorizations (id, tenant_id)
    DEFERRABLE INITIALLY DEFERRED;

-- The tenant-scoped access paths (the reuse-window query reads
-- acme_authorizations through (tenant_id, account_id, identifier); the
-- order listing sorts by created_at DESC, id, which the index suffix
-- serves without a post-filter sort).
CREATE INDEX IF NOT EXISTS acme_orders_tenant_account
    ON acme_orders (tenant_id, account_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS acme_authorizations_tenant_account
    ON acme_authorizations (tenant_id, account_id, identifier);
CREATE INDEX IF NOT EXISTS acme_challenges_tenant_authorization
    ON acme_challenges (tenant_id, authorization_id);