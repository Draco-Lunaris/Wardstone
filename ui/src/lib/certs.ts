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
  created_at: string;
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

/** One FULL CA row from `GET /api/v1/cas` (the `CaResponse` shape):
 * `CaSummary` plus the validity/key fields the CAs page renders and the
 * PUBLIC certificate PEM the AIA parser reads client-side (cert fields
 * only — keys never transit this layer). */
export interface Ca extends CaSummary {
  parent_id: string | null;
  key_type: string;
  not_before: string;
  not_after: string;
  cert_pem: string;
  created_at: string;
}

/** The `GET /api/v1/cas/{id}/crl` body (the newest published CRL); the
 * route answers 404 `not_found` when the CA has none. */
export interface CrlInfo {
  ca_id: string;
  issued_at: string;
  next_update: string;
  crl_pem: string;
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

/** The dashboard sieve's slim row, as `GET /api/v1/certificates/slim`
 * answers: the five small fields the expiring-soon list reads, WITHOUT the
 * full row's PEM/SAN bulk. Timestamps arrive RFC 3339. */
export interface SlimCertificate {
  id: string;
  subject: string;
  serial_hex: string;
  not_after: string;
  status: string;
}

/** The slim list's filter axes: the sieve pins `status="active"` and the
 * repo's 500-row clamp; `page`/`pageSize` are the shared paging. */
export interface SlimListFilters {
  status?: string;
  page?: number;
  pageSize?: number;
}

/** `GET /api/v1/certificates/slim` — registered BEFORE `/{id}` upstream,
 * so `slim` is never read as a certificate id. */
export function fetchCertificatesSlim(filters: SlimListFilters): Promise<SlimCertificate[]> {
  const params = new URLSearchParams();
  if (filters.status) {
    params.set("status", filters.status);
  }
  if (filters.page != null) {
    params.set("page", String(filters.page));
  }
  if (filters.pageSize != null) {
    params.set("page_size", String(filters.pageSize));
  }
  const qs = params.toString();
  return apiFetch<SlimCertificate[]>(
    qs ? `${CERTIFICATES_BASE}/slim?${qs}` : `${CERTIFICATES_BASE}/slim`,
  );
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

/** `GET /api/v1/cas` — the CA list (the issuer filter's options; the CAs
 * page renders the full rows). */
export function fetchCas(): Promise<Ca[]> {
  return apiFetch<Ca[]>("/api/v1/cas");
}

/** `GET /api/v1/cas/{id}/crl` — the CA's newest published CRL, or `null`
 * when none has been published yet (the route's 404 `not_found` — an
 * ordinary state, so the page can say so instead of erroring). Any other
 * failure surfaces as its ApiError verbatim. */
export async function fetchCasCrl(id: string): Promise<CrlInfo | null> {
  try {
    return await apiFetch<CrlInfo>(`/api/v1/cas/${encodeURIComponent(id)}/crl`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
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

// # The AIA field parser (certificate FIELDS only — keys never)
//
// One focused DER walk: find the certificate's
// id-pe-authorityInfoAccess extension (OID 1.3.6.1.5.5.7.1.1) and list
// its URI access descriptions, so the CAs page can show the OCSP /
// caIssuers endpoints operators would otherwise reach for `openssl x509`
// for. Everything malformed (not a PEM, not base64, broken DER, missing
// extension) yields entries-nothing: the parser is display-only and the
// PEM download remains the honest fallback.

/** One authority-information-access entry: the accessMethod's dotted OID
 * (`1.3.6.1.5.5.7.48.1` is OCSP, `.2` caIssuers) and its `URI:` general
 * name. */
export interface AiaAccess {
  method: string;
  uri: string;
}

const AIA_OID = new Uint8Array([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]);

export function parseAiaUris(pem: string): AiaAccess[] {
  const match = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  if (!match) {
    return [];
  }
  let der: Uint8Array;
  try {
    const binaryWindow = atob(match[0].replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""));
    der = Uint8Array.from(binaryWindow, (char) => char.charCodeAt(0));
  } catch {
    return [];
  }
  try {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    const certificate = readTlv(der, 0);
    const tbs = readTlv(der, certificate.dataStart);
    // Walk tbsCertificate's children; the extensions sit in the [3]
    // EXPLICIT tag (0xA3): SEQUENCE OF Extension, each
    // SEQUENCE { extnID OID, critical BOOLEAN?, extnValue OCTET STRING }.
    let offset = tbs.dataStart;
    while (offset < tbs.end) {
      const child = readTlv(der, offset);
      if (child.tag === 0xa3) {
        const access = walkAiaExtension(der, child);
        if (access) {
          return access;
        }
      }
      offset = child.next;
    }
    return [];
  } catch {
    return [];
  }
}

/** Inside the [3] EXPLICIT: find the AIA extension and decode its value
 * (itself a DER SEQUENCE OF AccessDescription) into URI entries. */
function walkAiaExtension(der: Uint8Array, explicit: Tlv): AiaAccess[] | null {
  const extensions = readTlv(der, explicit.dataStart); // SEQUENCE OF Extension
  let offset = extensions.dataStart;
  while (offset < extensions.end) {
    const extension = readTlv(der, offset);
    const oid = readTlv(der, extension.dataStart);
    const value = readTlv(der, oid.next); // OCTET STRING (critical BYTE is optional and between the two)
    if (matchesOid(der, oid, AIA_OID)) {
      const aia = new Uint8Array(der.subarray(value.dataStart, value.end));
      return readAccessDescriptions(aia);
    }
    offset = extension.next;
  }
  return null;
}

/** AuthorityInfoAccessSyntax ::= SEQUENCE OF
 * AccessDescription ::= SEQUENCE { accessMethod OID,
 * accessLocation [6] IMPLICIT IA5String (tag 0x86 = uniformResourceIdentifier). */
function readAccessDescriptions(aia: Uint8Array): AiaAccess[] {
  const entries: AiaAccess[] = [];
  const list = readTlv(aia, 0);
  let offset = list.dataStart;
  while (offset < list.end) {
    const access = readTlv(aia, offset);
    const method = readTlv(aia, access.dataStart);
    const location = readTlv(aia, method.next);
    if (method.tag === 0x06 && location.tag === 0x86) {
      entries.push({
        method: decodeOid(aia, method.dataStart, method.end),
        uri: new TextDecoder("ascii").decode(aia.subarray(location.dataStart, location.end)),
      });
    }
    offset = access.next;
  }
  return entries;
}

/** One BER tag-length-value, short-form tags (everything in an X.509
 * certificate is below tag 32) and short/long-form lengths. */
interface Tlv {
  tag: number;
  dataStart: number;
  end: number;
  next: number;
}

function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset + 2 > bytes.length) {
    throw new RangeError("truncated DER");
  }
  const tag = bytes[offset];
  let cursor = offset + 1;
  let length = bytes[cursor];
  cursor += 1;
  if (length > 0x7f) {
    const width = length & 0x7f;
    if (width === 0 || width > 4 || cursor + width > bytes.length) {
      throw new RangeError("unsupported DER length form");
    }
    length = 0;
    for (let index = 0; index < width; index += 1) {
      length = length * 256 + bytes[cursor + index];
    }
    cursor += width;
  }
  const end = cursor + length;
  if (end > bytes.length) {
    throw new RangeError("DER length overruns the buffer");
  }
  return { tag, dataStart: cursor, end, next: end };
}

/** Whether a TLV's contents equal the expected OID byte pattern. */
function matchesOid(bytes: Uint8Array, oid: Tlv, expected: Uint8Array): boolean {
  if (oid.tag !== 0x06 || oid.end - oid.dataStart !== expected.length) {
    return false;
  }
  return expected.every((byte, index) => bytes[oid.dataStart + index] === byte);
}

/** A DER OBJECT IDENTIFIER's contents as dotted decimal. */
function decodeOid(bytes: Uint8Array, start: number, end: number): string {
  const parts: number[] = [
    Math.floor(bytes[start] / 40),
    bytes[start] % 40,
  ];
  let value = 0;
  for (let cursor = start + 1; cursor < end; cursor += 1) {
    value = value * 128 + (bytes[cursor] & 0x7f);
    if ((bytes[cursor] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}