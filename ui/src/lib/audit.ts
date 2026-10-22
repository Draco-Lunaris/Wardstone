// The audit log's data layer: the `GET /api/v1/audit` paged, filtered
// list (newest-first ordering is the server's; every read is gated by
// `read_audit`). Types hand-mirror ws-core's `AuditEntry` as the route
// serializes it (crates/ws-api/src/routes/audit.rs).
//
// Task 2's encoding trap is pinned here: `from`/`to` are RFC 3339
// instants on the wire, and a query value carrying `+00:00` would see
// its `+` decoded as a SPACE by the form-encoding rules — a silently
// mangled instant and a 400 rejection. `rfc3339Z` therefore converts the
// filter form's wall-clock values to Z-suffix instants ONLY, and
// `buildAuditQuery` never accepts anything else for a date axis.

import { apiFetch } from "./api";

/** One audit entry (ws-core `AuditEntry`): who did what, to what, with
 * structured context — `details` is ids and labels, never key material. */
export interface AuditEntry {
  id: string;
  tenant_id: string;
  actor_type: string;
  auth_method: string;
  session_id: string | null;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  details: unknown;
  created_at: string;
}

/** The audit list's filter axes: `from`/`to` are Z-suffix RFC 3339
 * instants (as `rfc3339Z` produces), `action` is the exact action name.
 * Empty strings mean "unfiltered" and are omitted from the query. */
export interface AuditListFilters {
  from?: string;
  to?: string;
  action?: string;
  page?: number;
  /** The wire's `page_size`, snake_case per `AuditListQuery`. */
  pageSize?: number;
}

/** The audit page's client page size (the route's server default is 100;
 * the table paginates in a lighter rhythm). */
export const AUDIT_PAGE_SIZE = 50;

/**
 * Convert a wall-clock `datetime-local` value (or any string
 * `new Date` accepts) into a Z-suffix RFC 3339 instant — never a
 * `+00:00` offset. Garbage is `null`, never an Invalid-Date string
 * shipped to the wire.
 */
export function rfc3339Z(value: string): string | null {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  return date.toISOString();
}

/** `GET /api/v1/audit`'s query string: URLSearchParams encoding (Task 2's
 * discipline), empty axes omitted entirely, `page_size` snake_case. */
export function buildAuditQuery(filters: AuditListFilters): string {
  const params = new URLSearchParams();
  if (filters.from) {
    params.set("from", filters.from);
  }
  if (filters.to) {
    params.set("to", filters.to);
  }
  if (filters.action) {
    params.set("action", filters.action);
  }
  if (filters.page != null) {
    params.set("page", String(filters.page));
  }
  if (filters.pageSize != null) {
    params.set("page_size", String(filters.pageSize));
  }
  return params.toString();
}

/** `GET /api/v1/audit` — one page (the server orders newest first). */
export function fetchAuditEntries(filters: AuditListFilters): Promise<AuditEntry[]> {
  const qs = buildAuditQuery(filters);
  return apiFetch<AuditEntry[]>(qs ? `/api/v1/audit?${qs}` : "/api/v1/audit");
}