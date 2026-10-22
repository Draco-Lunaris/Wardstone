// The dashboard's stat-card mapping and the "expiring soon" list shape.
//
// 1. STAT CARDS — the three `GET /api/v1/certificates/statistics` numbers
//    map to the three dashboard tiles, in THE fixed order the wireframe
//    pins (active / revoked / expiring within 30 days), with the tile
//    labels decided once here, not in JSX.
// 2. THE EXPIRING LIST — the API has no "expiring soon" query axis: the
//    dashboard feeds `GET /certificates?status=active` into a pure
//    client-side selection (still-valid certificates whose `not_after`
//    lands inside the 30-day window, soonest first). The window matches
//    the server's statistic horizon (30 days), so the list can never
//    disagree with the tile above it — only under/over-run by the moment
//    the two fetches land.

import { describe, expect, it } from "vitest";

import { EXPIRY_WINDOW_DAYS, selectExpiringSoon, statCards } from "./stats";
import type { Certificate, CertificateStatistics } from "./certs";

const DAY_MS = 24 * 60 * 60 * 1000;

function cert(overrides: Partial<Certificate>): Certificate {
  return {
    id: "id",
    tenant_id: "t",
    ca_id: "c",
    profile_revision_id: null,
    profile_name: "Web Server",
    subject: "CN=www.example.com",
    serial_hex: "2a",
    san_dns: [],
    san_ips: [],
    key_type: "ecdsa_p256",
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2026-11-01T00:00:00Z",
    cert_pem: "-----BEGIN CERTIFICATE-----",
    status: "active",
    revoked_at: null,
    revocation_reason: null,
    revocation_detail: null,
    source: "manual",
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

const NOW = new Date("2026-10-22T00:00:00Z");

describe("statCards", () => {
  it("maps the three statistics to the pinned tile order and labels", () => {
    const stats: CertificateStatistics = { active: 12, revoked: 3, expiring_soon: 4 };
    expect(statCards(stats)).toEqual([
      { key: "active", label: "Active", value: 12 },
      { key: "revoked", label: "Revoked", value: 3 },
      { key: "expiring_soon", label: "Expiring within 30 days", value: 4 },
    ]);
  });
});

describe("selectExpiringSoon", () => {
  it("keeps only active certificates expiring within the 30-day window", () => {
    const rows = [
      cert({ id: "already-expired", not_after: "2026-10-01T00:00:00Z" }),
      cert({ id: "just-in", not_after: "2026-10-22T00:00:00Z" }),
      cert({ id: "window", not_after: "2026-11-20T23:59:59Z" }),
      cert({ id: "past-window", not_after: "2026-11-22T00:00:00Z" }),
      cert({ id: "revoked-in-window", status: "revoked", not_after: "2026-11-01T00:00:00Z" }),
      cert({ id: "garbage-time", not_after: "not-a-date" }),
    ];
    const ids = selectExpiringSoon(rows, NOW).map((row) => row.id);
    expect(ids).toEqual(["just-in", "window"]);
  });

  it("sorts the kept rows soonest-expiry first", () => {
    const rows = [
      cert({ id: "later", not_after: "2026-11-20T00:00:00Z" }),
      cert({ id: "sooner", not_after: "2026-10-25T00:00:00Z" }),
    ];
    expect(selectExpiringSoon(rows, NOW).map((row) => row.id)).toEqual(["sooner", "later"]);
  });

  it("treats the window boundary as closed on the outer edge", () => {
    const rows = [cert({ id: "edge", not_after: new Date(NOW.getTime() + 30 * DAY_MS).toISOString() })];
    expect(selectExpiringSoon(rows, NOW).map((row) => row.id)).toEqual(["edge"]);
  });

  it("honors a custom window in days", () => {
    const rows = [cert({ id: "seven", not_after: "2026-10-29T00:00:00Z" })];
    expect(selectExpiringSoon(rows, NOW, 7).map((row) => row.id)).toEqual(["seven"]);
  });

  it("pins the window constant to the server's 30-day statistic horizon", () => {
    expect(EXPIRY_WINDOW_DAYS).toBe(30);
  });
});