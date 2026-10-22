// The credentials lib layer: service identities (API tokens) and one-shot
// tokens, against the REAL wire shapes at
// crates/ws-api/src/routes/credentials.rs HEAD.
//
// Capability split on the wire (the route doc-comment's table): BOTH
// lists (`GET /service-identities`, `GET /one-shot-tokens`) sit behind
// `read_service_identities`; minting a service identity (and revoking
// one) behind `manage_api_tokens`; minting a one-shot token behind
// `manage_one_shot_tokens`. The UI gates each affordance on its own
// capability — never on a role string.
//
// Token plaintexts (`ws_at_`, `ws_ot_`) appear ONLY in the 201 mint
// bodies and flow from here into the page's copy-once display state —
// this layer never stores, logs, or re-sends them, and the pages treat
// them exactly like Task 15's private keys: shown once, gone on leave.

import { apiFetch } from "./api";

/** The server's one-shot window bounds in whole minutes
 * (`ONE_SHOT_MIN_TTL` = 1 minute, `ONE_SHOT_MAX_TTL` = 24 hours). The
 * mint body is `{ttl_minutes}` — NOT a seconds field. */
export const ONE_SHOT_TTL_MIN_MINUTES = 1;
export const ONE_SHOT_TTL_MAX_MINUTES = 1440;

/** One service identity, as a read DTO (never the token hash). */
export interface ServiceIdentity {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  capabilities: string[];
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

/** The 201 body of `POST /service-identities`: the token plaintext,
 * answered by no read endpoint, `Cache-Control: no-store`. */
export interface ServiceIdentityCreated {
  id: string;
  name: string;
  description: string | null;
  capabilities: string[];
  token: string;
  created_at: string;
}

/** The mint request body the wire expects. */
export interface CreateServiceIdentityBody {
  name: string;
  description?: string;
  capabilities: string[];
}

/** One one-shot token, as a read DTO (`minted_by` is the minting user's
 * id; the plaintext is never listed). */
export interface OneShotToken {
  id: string;
  minted_by: string | null;
  created_at: string;
  expires_at: string | null;
  used_at: string | null;
}

/** The 201 body of `POST /one-shot-tokens`: the token plaintext, shown
 * once. */
export interface OneShotTokenCreated {
  id: string;
  token: string;
  expires_at: string;
}

/**
 * The one-shot TTL bounds, client-side: whole minutes within the server's
 * 1..=1440 window. (The server re-checks and answers `bad_request` with
 * its own message; the client refuses to send what it already knows is
 * out of bounds.)
 */
export function isValidOneShotTtl(minutes: number): boolean {
  return (
    Number.isInteger(minutes) &&
    minutes >= ONE_SHOT_TTL_MIN_MINUTES &&
    minutes <= ONE_SHOT_TTL_MAX_MINUTES
  );
}

/** The mint payload, built pure so the page cannot drift: an invalid
 * window yields `null` (never a wire body), a valid one the exact
 * `{ttl_minutes}` object. */
export function buildOneShotPayload(ttlMinutes: number): { ttl_minutes: number } | null {
  if (!isValidOneShotTtl(ttlMinutes)) {
    return null;
  }
  return { ttl_minutes: ttlMinutes };
}

/**
 * The service-identity mint body: name trimmed, whitespace-only
 * description dropped from the JSON entirely (an absent key — the server
 * stores the description verbatim, so the UI's emptiness discipline is
 * the difference between "no description" and a phantom blank), and the
 * capability list passed through verbatim (an empty grant is legal; the
 * SERVER caps it at the creator's own set).
 */
export function buildServiceIdentityPayload(
  name: string,
  description: string | null | undefined,
  capabilities: string[],
): CreateServiceIdentityBody {
  const trimmedDescription = description?.trim();
  return trimmedDescription
    ? { name: name.trim(), description: trimmedDescription, capabilities }
    : { name: name.trim(), capabilities };
}

const SERVICE_IDENTITIES_BASE = "/api/v1/service-identities";
const ONE_SHOT_BASE = "/api/v1/one-shot-tokens";

/** `GET /service-identities`, one page. */
export function fetchServiceIdentities(filters: { page?: number; pageSize?: number } = {}) {
  return listPage(SERVICE_IDENTITIES_BASE, filters) as Promise<ServiceIdentity[]>;
}

/** `GET /one-shot-tokens`, one page (same capability as the other list). */
export function fetchOneShotTokens(filters: { page?: number; pageSize?: number } = {}) {
  return listPage(ONE_SHOT_BASE, filters) as Promise<OneShotToken[]>;
}

function listPage(
  base: string,
  { page, pageSize }: { page?: number; pageSize?: number },
): Promise<unknown> {
  const params = new URLSearchParams();
  if (page != null) {
    params.set("page", String(page));
  }
  if (pageSize != null) {
    params.set("page_size", String(pageSize));
  }
  const qs = params.toString();
  return apiFetch(qs ? `${base}?${qs}` : base);
}

/** `POST /service-identities` — the 201 carries the token exactly once. */
export function createServiceIdentity(body: CreateServiceIdentityBody): Promise<ServiceIdentityCreated> {
  return apiFetch<ServiceIdentityCreated>(SERVICE_IDENTITIES_BASE, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** `POST /service-identities/{id}/revoke` — idempotent (a 204). */
export async function revokeServiceIdentity(id: string): Promise<void> {
  await apiFetch(`${SERVICE_IDENTITIES_BASE}/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
  });
}

/** `POST /one-shot-tokens` — `ttl_minutes` between 1 and 1440; the 201
 * carries the token exactly once and its expiry. */
export function createOneShotToken(ttlMinutes: number): Promise<OneShotTokenCreated> {
  return apiFetch<OneShotTokenCreated>(ONE_SHOT_BASE, {
    method: "POST",
    body: JSON.stringify({ ttl_minutes: ttlMinutes }),
  });
}