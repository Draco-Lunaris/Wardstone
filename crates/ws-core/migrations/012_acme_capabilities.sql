-- 012: the ACME capability seeds.
--
-- Two capabilities join the access vocabulary for the ACME server
-- (RFC 8555) that Plan 4 builds, and this migration is the seed half of
-- that addition (the table half — `acme_accounts` and friends — landed
-- in migration 011):
--
--   read_acme              list and read ACME accounts and orders
--   manage_acme_accounts   create, deactivate, and delete ACME accounts,
--                          and mint ACME-token credentials
--
-- ISSUER AND VIEWER GAIN NOTHING: the two rows below are both `admin`.
-- The new capabilities are granted to `Admin` alone, through
-- `ws_core::models::rbac::ALL_CAPABILITIES` (which `role_capabilities`
-- returns verbatim for the Admin bundle) — the Issuer and Viewer bundles
-- are untouched.
--
-- ADD-ONLY on top of migration 007's seed: `ON CONFLICT DO NOTHING`
-- against the `(role, capability)` primary key, so re-running on a
-- database whose `role_capabilities` was migrated when migration 011
-- shipped cannot double-insert. After this migration the table is again
-- exactly `ws_core::models::rbac::role_capabilities()` — the one place
-- the bundles are defined.
INSERT INTO role_capabilities (role, capability) VALUES
  ('admin', 'read_acme'),
  ('admin', 'manage_acme_accounts')
ON CONFLICT DO NOTHING;