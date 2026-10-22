// The admin console's data layer: hand-written TS mirrors of the ws-api
// admin DTOs (crates/ws-api/src/routes/oidc.rs, profiles.rs, users.rs at
// the shapes those routes actually serialize) plus the pure payload
// builders the admin pages drive.
//
// Two disciplines this layer owns, both pinned by tests:
//
// 1. THE OIDC SECRET — `client_secret` never exists client-side beyond
//    the one field the operator is typing into (the stored secret is only
//    ever the boolean `client_secret_set`). A save where nothing was
//    typed maps the field to the ABSENT key (never `null`, never `""`) —
//    the server keeps the stored secret; a save where no secret is stored
//    and none was typed is refused client-side with the server's own 400
//    wording.
// 2. THE USER PATCH — a body that changes nothing is never built at all.
//    The server's PATCH route answers `{}` with 400 "nothing to update";
//    the UI disables the affordance instead of ever sending it.

import { apiFetch, ApiError } from "./api";
import type { Profile } from "./certs";

// # OIDC provider configuration (crates/ws-api/src/routes/oidc.rs)

/** The provider flavours the server admits (its PROVIDER_TYPES — anything
 * else is a clean 400). */
export const OIDC_PROVIDER_TYPES = ["keycloak", "azure", "custom"] as const;

/** `GET /api/v1/oidc/config`'s body — the management read, gated by
 * `manage_system` (NOT the public pre-auth `/config/status` flag the login
 * page uses). The stored secret is reduced to `client_secret_set`. */
export interface OidcConfig {
  provider_type: string;
  display_name: string;
  discovery_url: string;
  client_id: string;
  redirect_uri: string;
  scopes: string;
  client_secret_set: boolean;
}

/** `PUT /api/v1/oidc/config`'s body. `client_secret` is OPTIONAL: absent
 * (never null, never "") keeps the stored secret on an existing row, and
 * is REQUIRED (the server's 400) when first configuring. */
export interface UpsertOidcConfigBody {
  provider_type: string;
  display_name: string;
  discovery_url: string;
  client_id: string;
  client_secret?: string;
  redirect_uri: string;
  scopes: string;
}

/** A successful `POST /api/v1/oidc/config/test` probe: the fields
 * Wardstone's login flow consumes from discovery. */
export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

/** The form-shaped fields the OIDC page edits (the secret field holds the
 * NEW secret only while typing — the stored one is never echoed). */
export interface OidcFormFields {
  provider_type: string;
  display_name: string;
  discovery_url: string;
  client_id: string;
  /** Empty string means "unchanged" when a secret is stored. Never
   * trimmed or echoed anywhere. */
  client_secret: string;
  redirect_uri: string;
  scopes: string;
}

/** The callback path ws-web answers for each provider label, shown as
 * field help (Task 5's guidance): the operator substitutes their host. */
export function redirectUriPlaceholder(providerType: string): string {
  return `https://<your-host>/auth/ui/oidc/${providerType}/callback`;
}

/**
 * The redirect-scheme check, client-side and the server's exact rule
 * (oidc.rs `is_https_url`): an https prefix plus a non-empty authority
 * before the first path/query/fragment byte. Code handed back through the
 * redirect lives in the address bar — a downgraded scheme would leak it.
 */
export function isHttpsUrl(value: string): boolean {
  const rest = /^https:\/\//.test(value) ? value.slice("https://".length) : null;
  if (rest === null) {
    return false;
  }
  const authority = rest.split(/[/?#]/, 1)[0] ?? "";
  return authority.length > 0;
}

/** A payload result: a built body, or the client-side refusal worded the
 * way the server words its 400s. */
export type OidcPayloadResult =
  | { body: UpsertOidcConfigBody; error: null }
  | { body: null; error: string };

/**
 * Build the OIDC upsert body, pure. The secret discipline lives here:
 * an empty (untouched) secret field maps to the ABSENT key when a secret
 * is stored (`undefined`, never null), and is refused with the server's
 * own wording when none is stored. A typed secret passes verbatim — the
 * value is not trimmed, because a secret is exactly what the operator
 * typed. redirect_uri and provider_type are validated client-side so the
 * common mistakes die before a request leaves the page.
 */
export function buildOidcPayload(fields: OidcFormFields, secretIsStored: boolean): OidcPayloadResult {
  if (
    !OIDC_PROVIDER_TYPES.includes(
      fields.provider_type as (typeof OIDC_PROVIDER_TYPES)[number],
    )
  ) {
    return { body: null, error: "provider_type must be one of keycloak, azure, custom" };
  }
  if (!isHttpsUrl(fields.redirect_uri)) {
    return { body: null, error: "redirect_uri must be an https URL" };
  }
  if (fields.client_secret) {
    return { body: { ...fields, client_secret: fields.client_secret }, error: null };
  }
  if (!secretIsStored) {
    return {
      body: null,
      error: "client_secret is required when first configuring the provider",
    };
  }
  // Unchanged-and-set: the key is OMITTED from the object entirely —
  // `undefined` in a spread would survive into the JSON as nothing, but
  // the key itself carries intent ("keep the stored secret"), so it is
  // destructured off.
  const { client_secret: _keepStored, ...body } = fields;
  return { body, error: null };
}

/**
 * The discovery-test override, built from the CURRENT form values. Unlike
 * the save builder this never errors — `discover` on the wire uses only
 * the discovery URL, so an absent secret is simply the public-client
 * default. The body is ALWAYS well-formed: Task 5's deferred T5-M1 means
 * a malformed override body is read by the server as "no override" (it
 * probes the SAVED configuration instead), and the probe would then report
 * a pass that does not belong to the values the operator is looking at.
 */
export function buildOidcTestOverride(fields: OidcFormFields): UpsertOidcConfigBody {
  if (fields.client_secret) {
    return { ...fields, client_secret: fields.client_secret };
  }
  const { client_secret: _absent, ...override } = fields;
  return override;
}

const OIDC_CONFIG = "/api/v1/oidc/config";

/** `GET /api/v1/oidc/config`; a 404 means "not configured" — an ordinary
 * state the page renders as the first-configuration form, so it maps to
 * `null` instead of an error. */
export async function fetchOidcConfig(): Promise<OidcConfig | null> {
  try {
    return await apiFetch<OidcConfig>(OIDC_CONFIG);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
}

/** `PUT /api/v1/oidc/config` — the same shape as the GET comes back. */
export function saveOidcConfig(body: UpsertOidcConfigBody): Promise<OidcConfig> {
  return apiFetch<OidcConfig>(OIDC_CONFIG, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

/** `DELETE /api/v1/oidc/config` — 204 removes SSO; a 404 ("no OIDC
 * provider configuration exists") is the already-gone case and reads as
 * removed too. */
export async function removeOidcConfig(): Promise<void> {
  try {
    await apiFetch<void>(OIDC_CONFIG, { method: "DELETE" });
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return;
    }
    throw error;
  }
}

/** `POST /api/v1/oidc/config/test`, probing the override when given
 * (well-formed — see buildOidcTestOverride) or the saved configuration
 * otherwise. A failed probe is a 400 whose message is the discovery
 * error's display — surfaced verbatim. */
export function testOidcConfig(override: UpsertOidcConfigBody | null): Promise<OidcDiscovery> {
  return apiFetch<OidcDiscovery>(`${OIDC_CONFIG}/test`, {
    method: "POST",
    body: JSON.stringify(override ? { override } : {}),
  });
}

// # Certificate profiles (crates/ws-api/src/routes/profiles.rs)

/** The leaf key types a profile can pin (ws-ca `LeafKeyType`'s wire
 * spellings — the CSR's key must match EXACTLY at issuance). */
export const PROFILE_KEY_TYPES = ["rsa2048", "rsa3072", "ecdsa-p256", "ecdsa-p384", "ed25519"] as const;

/** The nine RFC 5280 key usages, in the shared vocabulary's snake_case
 * (ws-core `KeyUsagePurpose` — the RFC camelCase aliases are deliberately
 * not used anywhere in Wardstone). */
export const PROFILE_KEY_USAGES = [
  "digital_signature",
  "key_encipherment",
  "data_encipherment",
  "key_agreement",
  "key_cert_sign",
  "crl_sign",
  "content_commitment",
  "encipher_only",
  "decipher_only",
] as const;

/** The six RFC 5280 extended key usages (ws-ca `ExtKeyUsagePurpose`). */
export const PROFILE_EKUS = [
  "server_auth",
  "client_auth",
  "code_signing",
  "email_protection",
  "ocsp_signing",
  "time_stamping",
] as const;

/** The create/update body (the routes' `ProfileBody`, snake_case). The
 * name is the CREATE-only field: the update route revises the policy and
 * keeps the profile's name (the history's spine — every revision a live
 * profile ever had carries that name). */
export interface ProfileUpsertBody {
  name?: string;
  description?: string;
  key_type: string;
  key_usages: string[];
  eku: string[];
  lifetime_days: number;
  san_patterns: string[];
}

/** The form-shaped fields the profiles admin page edits. The lifetime is
 * the raw input text until parsed at submit time. */
export interface ProfileFormFields {
  name: string;
  description: string;
  key_type: string;
  key_usages: string[];
  eku: string[];
  lifetime_days: string;
  san_patterns: string[];
}

/** A payload result, like the OIDC one. */
export type ProfilePayloadResult =
  | { body: ProfileUpsertBody; error: null }
  | { body: null; error: string };

/**
 * Build the profile create/edit body, pure. On create the name is
 * required (trimmed — the server's same 400 wording otherwise); on edit
 * the name key is omitted even though the form still shows it locked.
 * A blank description maps to the ABSENT key (the server stores the
 * description verbatim, so the UI's emptiness discipline is the difference
 * between "no description" and a phantom blank). Lists pass through with
 * empty entries dropped — the server owns the deeper validation (unknown
 * usage spellings, unparsable SAN patterns, the fail-closed `*.`).
 */
export function buildProfilePayload(fields: ProfileFormFields, editing: boolean): ProfilePayloadResult {
  const lifetime = Number(fields.lifetime_days.trim());
  if (!Number.isInteger(lifetime) || lifetime < 1) {
    return { body: null, error: "a profile's lifetime must be at least one day" };
  }
  const body: ProfileUpsertBody = {
    key_type: fields.key_type,
    key_usages: fields.key_usages.filter((usage) => usage.length > 0),
    eku: fields.eku.filter((entry) => entry.length > 0),
    lifetime_days: lifetime,
    san_patterns: fields.san_patterns.filter((pattern) => pattern.length > 0),
  };
  if (!editing) {
    const name = fields.name.trim();
    if (!name) {
      return { body: null, error: "a profile name is required" };
    }
    body.name = name;
  }
  const description = fields.description.trim();
  if (description) {
    body.description = description;
  }
  return { body, error: null };
}

/** `POST /api/v1/profiles` — 201 with the profile and its first revision. */
export function createProfile(body: ProfileUpsertBody): Promise<Profile> {
  return apiFetch<Profile>("/api/v1/profiles", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** `PUT /api/v1/profiles/{id}` — appends an immutable revision. A
 * concurrent edit elsewhere is a 409 the UI surfaces verbatim (the caller
 * re-reads and retries). */
export function updateProfile(id: string, body: ProfileUpsertBody): Promise<Profile> {
  return apiFetch<Profile>(`/api/v1/profiles/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

/** `DELETE /api/v1/profiles/{id}` — 204, or the 409 whose fixed message
 * ("profile is referenced by certificates and cannot be deleted") the page
 * surfaces verbatim with its context. */
export function deleteProfile(id: string): Promise<void> {
  return apiFetch<void>(`/api/v1/profiles/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// # Users (crates/ws-api/src/routes/users.rs)

/** The role spellings the wire accepts (`Role`'s serde names). */
export const USER_ROLES = ["admin", "issuer", "viewer"] as const;

/** One user, as `GET /api/v1/users` and `PATCH /api/v1/users/{id}` answer
 * — no password hash, no sealed MFA material (the DTOs never carry them). */
export interface AdminUser {
  id: string;
  tenant_id: string;
  username: string;
  display_name: string;
  email: string;
  role: string;
  auth_provider: string;
  mfa_enabled: boolean;
  is_active: boolean;
  force_password_reset: boolean;
  last_login_at: string | null;
  created_at: string;
}

/** `POST /api/v1/users`'s body: a local account. The password transits
 * this layer once, into the POST, and lives in page state only while the
 * operator is typing it. */
export interface CreateUserBody {
  username: string;
  display_name?: string;
  email: string;
  role: string;
  password: string;
}

/** `PATCH /api/v1/users/{id}`'s body: either or both fields — never both
 * absent (the server 400s "nothing to update"; buildUserPatch refuses to
 * produce that shape at all). */
export interface UpdateUserBody {
  role?: string;
  is_active?: boolean;
}

/**
 * Build the user PATCH body, pure. `next.role === null` means "role
 * unchanged"; `next.is_active === null` means "flag unchanged". Only
 * CHANGED fields land in the body, and a body that would change nothing
 * is `null` — the empty PATCH the server refuses is unrepresentable.
 */
export function buildUserPatch(
  current: { role: string; is_active: boolean },
  next: { role: string | null; is_active: boolean | null },
): UpdateUserBody | null {
  const body: UpdateUserBody = {};
  if (next.role !== null && next.role !== current.role) {
    body.role = next.role;
  }
  if (next.is_active !== null && next.is_active !== current.is_active) {
    body.is_active = next.is_active;
  }
  return Object.keys(body).length === 0 ? null : body;
}

/** `GET /api/v1/users`. */
export function fetchUsers(): Promise<AdminUser[]> {
  return apiFetch<AdminUser[]>("/api/v1/users");
}

/** `POST /api/v1/users` — 201 with the new user. */
export function createUser(body: CreateUserBody): Promise<AdminUser> {
  return apiFetch<AdminUser>("/api/v1/users", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** `PATCH /api/v1/users/{id}` — role assignment / activation. The
 * last-admin guard's 409 ("refusing to remove the last active
 * administrator") surfaces verbatim. */
export function patchUser(id: string, body: UpdateUserBody): Promise<AdminUser> {
  return apiFetch<AdminUser>(`/api/v1/users/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}