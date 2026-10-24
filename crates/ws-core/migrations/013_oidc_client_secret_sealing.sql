-- Sealing the OIDC client secret at rest (threat-model gap G2). Migration
-- 007's own comment booked this as "Task 5's"; no later migration shipped
-- it, so secrets configured before this migration sat as plaintext TEXT.
--
-- ADD-ONLY as always: the TEXT column stays in place as the LEGACY slot —
-- fresh installs never write plaintext into it anymore, and rows configured
-- before this migration are migrated LAZILY on first admin read (the repo
-- layer reseals under the SecretBox key and clears the column; SQL cannot
-- reach the application-held key, by design).
ALTER TABLE oidc_config ADD COLUMN client_secret_encrypted BYTEA;
ALTER TABLE oidc_config ADD COLUMN client_secret_nonce BYTEA;
