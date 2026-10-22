// The audit lib layer's pins (Task 16, tests first):
//
// 1. THE Z-SUFFIX RFC 3339 ENCODING — Task 2 pinned the trap: a query
//    value carrying `+00:00` is decoded with `+` as a SPACE by the
//    form-encoding rules, so the instant silently degrades into an axum
//    400 rejection. Every `from`/`to` the UI sends is therefore produced
//    by `rfc3339Z`, which always ends in `Z` and NEVER contains a `+`.
// 2. THE QUERY BUILDER — the axes (`from`, `to`, `action`, `page`,
//    `page_size`) are URLSearchParams-encoded, empty axes are OMITTED
//    entirely (never `action=`), and `page_size` uses the wire's
//    snake_case spelling (`AuditListQuery`, crates/ws-api/src/routes/
//    audit.rs).
// 3. THE FETCHER — one page, newest first (the server's ordering), and
//    every failure surfaces as the ApiError verbatim.
//
// Timezone pinning: `rfc3339Z` feeds a wall-clock `datetime-local` value
// through `new Date(...)`, so its LOCAL reading is converted to UTC. The
// tests run under TZ=UTC (set below, before any Date is constructed) to
// keep the expected strings deterministic.

declare const process: { env: Record<string, string | undefined> };

process.env.TZ = "UTC";

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "./api";
import { AUDIT_PAGE_SIZE, buildAuditQuery, fetchAuditEntries, rfc3339Z } from "./audit";
import type { AuditEntry } from "./audit";

afterEach(() => {
  vi.unstubAllGlobals();
});

const ENTRY: AuditEntry = {
  id: "11111111-1111-4111-8111-000000000001",
  tenant_id: "22222222-2222-4222-8222-000000000002",
  actor_type: "user",
  auth_method: "password",
  session_id: null,
  actor_id: "alice",
  action: "cert_issued",
  target_type: "certificate",
  target_id: "33333333-3333-4333-8333-000000000003",
  details: { profile: "Web Server" },
  created_at: "2026-10-22T10:00:00Z",
};

describe("rfc3339Z", () => {
  it("converts a wall-clock datetime-local value to a Z-suffix instant", () => {
    expect(rfc3339Z("2026-10-22T12:34:56")).toBe("2026-10-22T12:34:56.000Z");
  });

  it("keeps an input that already carries a Z suffix unchanged in meaning", () => {
    expect(rfc3339Z("2026-10-22T12:34:56Z")).toBe("2026-10-22T12:34:56.000Z");
  });

  it("accepts a date-only value as its midnight instant", () => {
    expect(rfc3339Z("2026-10-22")).toBe("2026-10-22T00:00:00.000Z");
  });

  it("returns null for garbage instead of shipping Invalid Date to the wire", () => {
    expect(rfc3339Z("not-a-date")).toBeNull();
    expect(rfc3339Z("")).toBeNull();
  });
});

describe("buildAuditQuery", () => {
  it("emits the Z-suffix instants, percent-encoded by URLSearchParams", () => {
    expect(buildAuditQuery({ from: "2026-10-01T00:00:00.000Z", to: "2026-10-31T23:59:59.000Z" })).toBe(
      "from=2026-10-01T00%3A00%3A00.000Z&to=2026-10-31T23%3A59%3A59.000Z",
    );
  });

  it("NEVER emits `+00:00` — the Task 2 encoding trap stays closed", () => {
    const qs = buildAuditQuery({
      from: rfc3339Z("2026-10-22T00:00:00") as string,
      to: rfc3339Z("2026-10-22T23:59:59") as string,
    });
    expect(qs).not.toContain("+");
    expect(qs.endsWith(".000Z") || qs.includes(".000Z")).toBe(true);
    // The whole string decodes back to what the operator meant.
    const back = new URLSearchParams(qs);
    expect(back.get("from")).toBe("2026-10-22T00:00:00.000Z");
    expect(back.get("to")).toBe("2026-10-22T23:59:59.000Z");
  });

  it("carries the action filter verbatim and pages in snake_case", () => {
    expect(buildAuditQuery({ action: "cert_issued", page: 2, pageSize: 50 })).toBe(
      "action=cert_issued&page=2&page_size=50",
    );
  });

  it("omits empty axes instead of sending empty values", () => {
    expect(buildAuditQuery({ from: "", to: "", action: "" })).toBe("");
  });

  it("keeps page 0 when it is set explicitly", () => {
    expect(buildAuditQuery({ page: 0, pageSize: AUDIT_PAGE_SIZE })).toBe(
      `page=0&page_size=${AUDIT_PAGE_SIZE}`,
    );
  });
});

describe("fetchAuditEntries", () => {
  it("GETs one page of the audit route with the built query", async () => {
    const pagesSeen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      pagesSeen.push(String(input));
      return new Response(JSON.stringify([ENTRY]), { status: 200 });
    }));
    const entries = await fetchAuditEntries({ action: "cert_issued", page: 1 });
    expect(entries).toEqual([ENTRY]);
    expect(pagesSeen).toEqual(["/api/v1/audit?action=cert_issued&page=1"]);
  });

  it("surfaces a failed response as the ApiError verbatim", async () => {
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(
        JSON.stringify({ error: { code: "bad_request", message: "a malformed datetime" } }),
        { status: 400, headers: { "content-type": "application/json" } },
      ),
    ));
    const caught = await fetchAuditEntries({}).then(
      () => null,
      (error: unknown) => error,
    );
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).message).toBe("a malformed datetime");
  });
});