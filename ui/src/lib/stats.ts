// The dashboard's pure view layer: the statistics → stat-card mapping and
// the client-side "expiring soon" selection. The API exposes no dedicated
// "expiring" query axis, so the dashboard feeds
// `GET /api/v1/certificates?status=active` into `selectExpiringSoon` — the
// window (still-valid certificates whose `not_after` falls inside the
// coming 30 days, soonest first) deliberately matches the server's
// `expiring_soon` horizon pinned in crates/ws-api/src/routes/certificates.rs,
// so the list can only drift from its tile by the moment between the two
// fetches.

import type { Certificate, CertificateStatistics } from "./certs";

/** The server-side 30-day expiry horizon (certificates.rs pins it). */
export const EXPIRY_WINDOW_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;

/** One dashboard tile, mapped once here so the page's JSX stays layout
 * only. Order is the wireframe's: active, revoked, expiring soon. */
export interface StatCard {
  key: string;
  label: string;
  value: number;
}

export function statCards(stats: CertificateStatistics): StatCard[] {
  return [
    { key: "active", label: "Active", value: stats.active },
    { key: "revoked", label: "Revoked", value: stats.revoked },
    { key: "expiring_soon", label: "Expiring within 30 days", value: stats.expiring_soon },
  ];
}

/** The dashboard's expiring list: `active` certificates with a parsable
 * `not_after` not already past and inside the window, sorted soonest
 * first (a certificate expiring exactly `now` still counts; anything
 * strictly earlier is already expired). Unparsable timestamps are
 * dropped (a bad date is never shown as "expiring"). */
export function selectExpiringSoon(
  certificates: Certificate[],
  now: Date = new Date(),
  windowDays: number = EXPIRY_WINDOW_DAYS,
): Certificate[] {
  const nowMs = now.getTime();
  return certificates
    .map((certificate) => ({ certificate, at: new Date(certificate.not_after).getTime() }))
    .filter(
      ({ certificate, at }) =>
        certificate.status === "active" &&
        Number.isFinite(at) &&
        at >= nowMs &&
        at <= nowMs + windowDays * DAY_MS,
    )
    .sort((a, b) => a.at - b.at)
    .map(({ certificate }) => certificate);
}