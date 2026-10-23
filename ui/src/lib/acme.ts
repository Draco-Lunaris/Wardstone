// The ACME lib layer: the operator's window over the /api/v1/acme REST
// projection (crates/ws-api/src/routes/acme.rs, "The UI-facing REST
// projection" section at HEAD). The JWS machine surface
// (`/acme/{tenant}/…`) is deliberately NEVER touched from here — no
// nonces, no JWS, no problem documents. These are ordinary
// capability-gated routes:
//
// - BOTH reads (`GET /accounts`, `GET /accounts/{id}`, `GET /orders`) sit
//   behind `read_acme`; the deactivation
//   (`POST /accounts/{id}/deactivate`) behind `manage_acme_accounts`
//   (migration 012's seed). The UI gates every affordance on the
//   capability, never on a role string.
// - `orders_count` arrives precomputed per account (a LEFT-JOIN count of
//   EVERY order the account placed, any status); the orders route scopes
//   to exactly one of `account_id` / `certificate_id` — naming neither is
//   a 400 the client refuses to provoke.
// - `identifiers` is the RFC 8555 array stored VERBATIM on the server, so
//   this layer treats it as untrusted shape and reduces it through
//   `identifierValues` (malformed entries are dropped, never guessed).
// - Deactivation is idempotent server-side: a repeat answers 0/0 and no
//   second audit row, so a double click is harmless.

import { apiFetch } from "./api";

/** The `acme_accounts.status` spellings (the stored TEXT column's
 * vocabulary). */
export const ACME_ACCOUNT_STATUSES = ["pending", "valid", "deactivated"] as const;

/** The `acme_orders.status` spellings (the stored TEXT column's
 * vocabulary). */
export const ACME_ORDER_STATUSES = [
  "pending",
  "ready",
  "processing",
  "valid",
  "invalid",
] as const;

/** One RFC 8555 identifier entry, display-shaped. */
export interface AcmeIdentifier {
  type: string;
  value: string;
}

/** One ACME account as `GET /api/v1/acme/accounts` answers: identity
 * fields plus the precomputed `orders_count`. Timestamps arrive RFC 3339,
 * statuses as the stored snake_case spellings. */
export interface AcmeAccount {
  id: string;
  /** The account key's RFC 7638 thumbprint — the account's human-facing
   * identity (the kid URL's final segment). */
  jwk_thumbprint: string;
  status: string;
  tos_agreed_at: string | null;
  contact: string | null;
  created_at: string;
  orders_count: number;
}

/** One ACME order as `GET /api/v1/acme/orders` and the account detail's
 * `orders` array answer. `identifiers` is the raw RFC 8555 array the
 * order stored verbatim — reduced through `identifierValues` before
 * display. */
export interface AcmeOrder {
  id: string;
  account_id: string;
  status: string;
  profile_name: string;
  identifiers: unknown;
  certificate_id: string | null;
  error: string | null;
  expires_at: string;
  created_at: string;
}

/** The account detail (`GET /api/v1/acme/accounts/{id}`): the list's
 * fields plus the recent-orders window (the full history pages through
 * `GET /orders?account_id=`). */
export interface AcmeAccountDetail extends AcmeAccount {
  orders: AcmeOrder[];
}

/** `POST /api/v1/acme/accounts/{id}/deactivate`'s body: the account's new
 * state and the two cascade counts (0/0 on the idempotent repeat). */
export interface AcmeDeactivateResponse {
  id: string;
  status: string;
  authorizations_invalidated: number;
  orders_invalidated: number;
}

/** The `GET /api/v1/acme/orders` filter axes: exactly one of `accountId`
 * or `certificateId` (plus the shared paging). */
export interface AcmeOrdersFilters {
  accountId?: string;
  certificateId?: string;
  page?: number;
  pageSize?: number;
}

/**
 * Build the orders route's query string. URLSearchParams does the
 * encoding; empty axes are omitted entirely; `page_size` uses the wire's
 * snake_case spelling — the same discipline the certificates list pins.
 */
export function buildAcmeOrdersQuery(filters: AcmeOrdersFilters): string {
  const params = new URLSearchParams();
  if (filters.accountId) {
    params.set("account_id", filters.accountId);
  }
  if (filters.certificateId) {
    params.set("certificate_id", filters.certificateId);
  }
  if (filters.page != null) {
    params.set("page", String(filters.page));
  }
  if (filters.pageSize != null) {
    params.set("page_size", String(filters.pageSize));
  }
  return params.toString();
}

/**
 * The order's identifier values, display-shaped: the RFC 8555 identifiers
 * array is stored (and answered) verbatim, so entries that are not
 * objects or carry no string `value` are DROPPED — a corruption-only
 * branch (the mint route validates the whole array), never a guess.
 */
export function identifierValues(order: Pick<AcmeOrder, "identifiers">): string[] {
  if (!Array.isArray(order.identifiers)) {
    return [];
  }
  return order.identifiers
    .map((entry) =>
      typeof entry === "object" && entry !== null && typeof (entry as AcmeIdentifier).value === "string"
        ? { type: String((entry as AcmeIdentifier).type ?? ""), value: (entry as AcmeIdentifier).value as string }
        : null,
    )
    .filter((entry): entry is AcmeIdentifier => entry !== null)
    .map((entry) => entry.value);
}

const ACME_BASE = "/api/v1/acme";

/** `GET /api/v1/acme/accounts` — one page (shared paging). */
export function fetchAcmeAccounts(
  filters: { page?: number; pageSize?: number } = {},
): Promise<AcmeAccount[]> {
  const params = new URLSearchParams();
  if (filters.page != null) {
    params.set("page", String(filters.page));
  }
  if (filters.pageSize != null) {
    params.set("page_size", String(filters.pageSize));
  }
  const qs = params.toString();
  return apiFetch<AcmeAccount[]>(qs ? `${ACME_BASE}/accounts?${qs}` : `${ACME_BASE}/accounts`);
}

/** `GET /api/v1/acme/accounts/{id}` — the detail with its recent orders
 * (another tenant's account is one 404). */
export function fetchAcmeAccount(id: string): Promise<AcmeAccountDetail> {
  return apiFetch<AcmeAccountDetail>(`${ACME_BASE}/accounts/${encodeURIComponent(id)}`);
}

/** `GET /api/v1/acme/orders` — the orders of one account, or the order
 * behind one certificate (a certificate with no order answers an empty
 * list, an ordinary state the page renders — never an error). */
export function fetchAcmeOrders(filters: AcmeOrdersFilters): Promise<AcmeOrder[]> {
  const qs = buildAcmeOrdersQuery(filters);
  return apiFetch<AcmeOrder[]>(qs ? `${ACME_BASE}/orders?${qs}` : `${ACME_BASE}/orders`);
}

/** `POST /api/v1/acme/accounts/{id}/deactivate` — the one-way gate +
 * cascade; the server answers the two invalidated counts. */
export function deactivateAcmeAccount(id: string): Promise<AcmeDeactivateResponse> {
  return apiFetch<AcmeDeactivateResponse>(
    `${ACME_BASE}/accounts/${encodeURIComponent(id)}/deactivate`,
    { method: "POST", body: JSON.stringify({}) },
  );
}