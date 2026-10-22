// The certificate domain's data layer: hand-written TS mirrors of the
// ws-api DTOs (crates/ws-api/src/routes/certificates.rs at the shapes the
// routes actually serialize) plus the pure builders the pages drive.
//
// Everything here goes through `apiFetch` — one doorway, one error type.
// The ONE exception is the chain route, whose body is `application/
// x-pem-file` TEXT, not JSON: `apiFetch`'s success path parses JSON, so
// `fetchText` mirrors its GET semantics (no CSRF header — GET is exempt)
// and its error decoding instead.
//
// The private key of a server-generated certificate passes through this
// layer ONLY as the string the 201 response carries. It is wrapped in a
// blob for the one-time download (`makeOneTimeDownload`), revoked on
// unmount by the issuance page's cleanup, and never stored, logged, or
// sent anywhere.

import { apiFetch, ApiError } from "./api";

/** The nine RFC 5280 §5.3.1 revocation reasons, in their exact
 * snake_case wire spellings (serde's names — the same strings ws-worker's
 * CRL/OCSP builders parse, stored verbatim in the audit details). */
export const REVOCATION_REASONS = [
  "unspecified",
  "key_compromise",
  "ca_compromise",
  "affiliation_changed",
  "superseded",
  "cessation_of_operation",
  "certificate_hold",
  "privilege_withdrawn",
  "aa_compromise",
] as const;

export type RevocationReason = (typeof REVOCATION_REASONS)[number];

/** A certificate as `GET /api/v1/certificates` and
 * `GET /api/v1/certificates/{id}` answer (the `CertificateResponse`
 * shape; no key fields exist server-side). Timestamps arrive RFC 3339. */
export interface Certificate {
  id: string;
  tenant_id: string;
  ca_id: string;
  profile_revision_id: string | null;
  profile_name: string;
  subject: string;
  serial_hex: string;
  san_dns: string[];
  san_ips: string[];
  key_type: string;
  not_before: string;
  not_after: string;
  cert_pem: string;
  /** `active` or `revoked` (the `CertStatus` column spellings). */
  status: string;
  revoked_at: string | null;
  revocation_reason: string | null;
  revocation_detail: string | null;
  source: string;
  created_at: string;
}

/** `GET /api/v1/certificates/statistics`'s body. */
export interface CertificateStatistics {
  active: number;
  revoked: number;
  /** Active certificates expiring before now + 30 days. */
  expiring_soon: number;
}

/** The 201 body of `POST /api/v1/certificates` (`IssuedCertificateReponse`
 * on the wire — the UI never re-types that typo). `private_key_pem` is
 * present ONLY on the server-key-generation path and is answered by no
 * read endpoint ever again. */
export interface IssuedCertificate {
  certificate_id: string;
  cert_pem: string;
  /** The decimal serial, as issued. */
  serial: string;
  /** The lowercase-hex serial, no leading zeros. */
  serial_hex: string;
  profile_revision_id: string;
  profile_name: string;
  not_before: string;
  not_after: string;
  private_key_pem?: string;
}

/** The issuance request body: WITH `csr_pem` selects the CSR path
 * (capability `issue`); WITHOUT it the server key-generation path
 * (capability `generate_leaf_key`). There is no revision pin — the
 * server reads the profile's current revision. */
export interface IssueCertificateBody {
  profile_id: string;
  subject_cn: string;
  sans: string[];
  csr_pem?: string;
}

/** A profile as `GET /api/v1/profiles` answers — the LIST does not
 * hydrate `current_revision` (only `GET /api/v1/profiles/{id}` does), so
 * the issuance page fetches the single profile for its pinned policy. */
export interface Profile {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  current_revision: ProfileRevision | null;
  created_at: string;
}

export interface ProfileRevision {
  id: string;
  revision: number;
  name: string;
  key_type: string;
  key_usages: string[];
  eku: string[];
  lifetime_days: number;
  san_patterns: string[];
}

/** One CA, the fields the issuer filter needs
 * (`GET /api/v1/cas`'s `CaResponse`, trimmed to its display fields). */
export interface CaSummary {
  id: string;
  tenant_id: string;
  name: string;
  subject: string;
  is_root: boolean;
}

/** `POST /api/v1/certificates/{id}/revoke`'s body. The reason is TYPED —
 * one of the nine snake_case names; the detail is optional free text the
 * server refuses past 2000 characters. */
export interface RevokeBody {
  reason: RevocationReason;
  detail?: string;
}

/** The revoke route's response: the certificate id, its status, and the
 * stored detail — the request's on a first revoke, the FIRST revoke's on
 * the idempotent already-revoked no-op (a 200, never a conflict). */
export interface RevokeResponse {
  id: string;
  status: string;
  detail: string | null;
}

/** The `GET /api/v1/certificates` filter axes, all optional. Empty
 * strings mean "unfiltered" and are omitted from the query. */
export interface CertificateListFilters {
  /** `active` | `revoked` (the wire's only values). */
  status?: string;
  /** The profile NAME (the display label), not an id. */
  profile?: string;
  /** The issuing CA's id. */
  ca?: string;
  /** Substring search across subject | serial_hex | SANs. */
  q?: string;
  page?: number;
  pageSize?: number;
}

/**
 * Build the list route's query string from the filter axes.
 *
 * URLSearchParams does the encoding (names with spaces land as `+`,
 * `&`/`=`/`?` percent-encode — Task 2's discipline), empty axes are
 * omitted entirely, and `page_size` uses the wire's snake_case spelling.
 */
export function buildCertificateListQuery(filters: CertificateListFilters): string {
  const params = new URLSearchParams();
  if (filters.status) {
    params.set("status", filters.status);
  }
  if (filters.profile) {
    params.set("profile", filters.profile);
  }
  if (filters.ca) {
    params.set("ca", filters.ca);
  }
  if (filters.q) {
    params.set("q", filters.q);
  }
  if (filters.page != null) {
    params.set("page", String(filters.page));
  }
  if (filters.pageSize != null) {
    params.set("page_size", String(filters.pageSize));
  }
  return params.toString();
}

const CERTIFICATES_BASE = "/api/v1/certificates";

/** `GET /api/v1/certificates` — one page through the filter axes. */
export function fetchCertificates(filters: CertificateListFilters): Promise<Certificate[]> {
  const qs = buildCertificateListQuery(filters);
  return apiFetch<Certificate[]>(qs ? `${CERTIFICATES_BASE}?${qs}` : CERTIFICATES_BASE);
}

/** `GET /api/v1/certificates/statistics`. */
export function fetchCertificateStatistics(): Promise<CertificateStatistics> {
  return apiFetch<CertificateStatistics>(`${CERTIFICATES_BASE}/statistics`);
}

/** `GET /api/v1/certificates/{id}` (another tenant's is a 404). */
export function fetchCertificate(id: string): Promise<Certificate> {
  return apiFetch<Certificate>(`${CERTIFICATES_BASE}/${encodeURIComponent(id)}`);
}

/** `POST /api/v1/certificates` — the dual-path issuance (the body's
 * `csr_pem` selects the path; the capability the server demands follows
 * from it). The response is Cache-Control: no-store. */
export function issueCertificate(body: IssueCertificateBody): Promise<IssuedCertificate> {
  return apiFetch<IssuedCertificate>(CERTIFICATES_BASE, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * The revoke request body, built pure so the pages can't drift: the
 * detail is trimmed, and empty/whitespace detail is dropped from the JSON
 * entirely (an absent key, never `""` or `null` — the server stores the
 * detail verbatim, so the UI's emptiness discipline is the difference
 * between "no detail" and a phantom blank).
 */
export function buildRevokePayload(reason: RevocationReason, detail?: string | null): RevokeBody {
  const trimmed = detail?.trim();
  return trimmed ? { reason, detail: trimmed } : { reason };
}

/** `POST /api/v1/certificates/{id}/revoke` — idempotent server-side. */
export function revokeCertificate(
  id: string,
  reason: RevocationReason,
  detail?: string | null,
): Promise<RevokeResponse> {
  return apiFetch<RevokeResponse>(`${CERTIFICATES_BASE}/${encodeURIComponent(id)}/revoke`, {
    method: "POST",
    body: JSON.stringify(buildRevokePayload(reason, detail)),
  });
}

/** `GET /api/v1/certificates/{id}/chain` TEXT: the leaf-first PEM
 * (certificate, then the issuing chain up to the root). Mirrors
 * `apiFetch`'s error decoding — the JSON envelope, else the plain body —
 * because the SUCCESS body is PEM text, not JSON. */
export async function fetchText(path: string): Promise<string> {
  const response = await fetch(path);
  if (response.ok) {
    return response.text();
  }
  const status = response.status;
  const contentType = response.headers.get("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const body: unknown = await response.json();
      const error = (body as { error?: { code?: string; message?: string } })?.error;
      if (error && typeof error === "object") {
        throw new ApiError(
          String(error.code ?? `http_${status}`),
          String(error.message ?? ""),
          status,
        );
      }
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      // A malformed JSON body falls through to the plain-text handling.
    }
  }
  let message = "";
  try {
    message = (await response.text()).trim();
  } catch {
    // The body is unreadable; the generic message below still applies.
  }
  throw new ApiError(
    status === 429 ? "rate_limited" : `http_${status}`,
    message || `the request failed with status ${status}`,
    status,
  );
}

/** `GET /api/v1/profiles` — the list (no current revisions). */
export function fetchProfiles(): Promise<Profile[]> {
  return apiFetch<Profile[]>("/api/v1/profiles");
}

/** `GET /api/v1/profiles/{id}` — WITH the current revision. */
export function fetchProfile(id: string): Promise<Profile> {
  return apiFetch<Profile>(`/api/v1/profiles/${encodeURIComponent(id)}`);
}

/** `GET /api/v1/cas` — the CA list (the issuer filter's options). */
export function fetchCas(): Promise<CaSummary[]> {
  return apiFetch<CaSummary[]>("/api/v1/cas");
}

/**
 * A blob URL the caller MUST revoke: wrap the one-time private key in a
 * downloadable blob and hand back the only three things anyone may do
 * with it. `revoke()` frees the URL (idempotent — the unmount cleanup
 * calls it unconditionally), and a download after the revoke is refused
 * rather than resurrecting freed memory. Nothing here logs or stores the
 * content anywhere besides the in-memory blob.
 */
export interface OneTimeDownload {
  filename: string;
  blobUrl: string;
  download(): void;
  revoke(): void;
}

export function makeOneTimeDownload(content: string, mime: string, filename: string): OneTimeDownload {
  const blobUrl = URL.createObjectURL(new Blob([content], { type: mime }));
  let revoked = false;
  return {
    filename,
    blobUrl,
    download() {
      if (!revoked) {
        triggerAnchorDownload(blobUrl, filename);
      }
    },
    revoke() {
      if (!revoked) {
        revoked = true;
        URL.revokeObjectURL(blobUrl);
      }
    },
  };
}

/** Download pre-built content as a file: create the blob URL, click an
 * anchor, free the URL — the whole life fits inside the click handler. */
export function downloadText(content: string, mime: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  triggerAnchorDownload(url, filename);
  URL.revokeObjectURL(url);
}

/** Synthesize the anchor click a blob download needs. */
function triggerAnchorDownload(url: string, filename: string): void {
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

/**
 * The role-gating discipline, pure: the session's capabilities are
 * snake_case names and the UI gates every sensitive affordance on them
 * (never on role strings). A missing identity holds nothing.
 */
export function hasCapability(capabilities: string[] | undefined, capability: string): boolean {
  return capabilities?.includes(capability) ?? false;
}

/**
 * The issuance form's SAN textarea: one name per line, blanks dropped,
 * each trimmed. IP literals stay plain strings — the SERVER classifies
 * DNS vs IP (the same `parse::<IpAddr>` both paths run), so the client
 * never pre-classifies wrongly.
 */
export function parseSans(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}