-- Migration 010: the optional free-form revocation detail.
--
-- `certificates.revocation_reason` stores the RFC 5280 section 5.3.1
-- name the CRL/OCSP builders parse (via ws-worker's `reason_from_str`);
-- it has no room for the operator's free-text note. The detail column
-- carries that note verbatim, ADD-ONLY alongside the reason: it is
-- never parsed, never published in a CRL/OCSP extension, and every
-- existing row keeps `NULL`.
ALTER TABLE certificates ADD COLUMN revocation_detail TEXT NULL;