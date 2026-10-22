-- 009: the audit_log actor auth-method columns (Plan 2).
--
-- `audit_log` gains the columns Plan 2's access vocabulary demands:
--
--   auth_method TEXT NOT NULL: how the actor authenticated -- the TEXT
--     form of `ws_core::models::rbac::AuthMethod` (`session`, `api_token`,
--     `one_shot`, `system`, `acme_account`). NOT NULL because every audit
--     row describes an action someone or something took, and the how is
--     now part of that record; the column lands together with the code
--     that populates it (this migration ships in the same task as the
--     `AuditRepo::record` binding and the worker's own audit write), so
--     there is never a window where the schema demands a value the insert
--     path does not supply.
--
--   session_id uuid NULL: for a human session actor, the browser session
--     the action was attributed to -- what makes an audited user action
--     traceable to a revocable session. Machine actors have no session,
--     so the column stays nullable and is NOT backfilled; `record` binds
--     it explicitly (NULL for machines).
--
-- The backfill: rows written before this migration have no method, and
-- the CASE covers EVERY `actor_type` value the closed enum has -- `user`
-- maps to `session`, every non-user actor (`system`, and `acme_account`
-- until ACME lands in a later plan, which will write its own method) maps
-- to `system` -- so no row is left NULL and the SET NOT NULL cannot abort.
-- Existing `actor_type` spellings are the ones `ActorType::as_str`
-- writes, so the WHEN arms are exhaustive over the data in the column.

ALTER TABLE audit_log ADD COLUMN auth_method TEXT NULL;
ALTER TABLE audit_log ADD COLUMN session_id uuid NULL;
UPDATE audit_log SET auth_method = CASE actor_type
    WHEN 'user' THEN 'session'
    WHEN 'system' THEN 'system'
    ELSE 'system' END
  WHERE auth_method IS NULL;
ALTER TABLE audit_log ALTER COLUMN auth_method SET NOT NULL;