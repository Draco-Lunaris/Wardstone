// The dashboard consumes the SLIM route for its expiring-soon sieve: the
// list request is exactly `GET /certificates/slim?status=active&page_size=
// 500` (the repo clamp), the full list route is never touched by the
// sieve, each row links to its detail route, and the table reads only the
// slim fields (no Profile column — the five-slim-field projection is all
// the sieve sees). The role="note" incompleteness warning keeps its
// full-page behavior.

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import Dashboard from "./Dashboard";

vi.mock("../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "op", tenant_id: "t", capabilities: ["read_certificates"] },
  }),
}));

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const SOON_ISO = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();

const SLIM_ROWS = [
  {
    id: "55555555-5555-4555-8555-000000000005",
    subject: "CN=soonest.example",
    serial_hex: "aa55",
    not_after: SOON_ISO,
    status: "active",
  },
];

const SLIM_ROUTE = "GET /api/v1/certificates/slim?status=active&page_size=500";

/** A GET dispatching fetch mock (each request gets a fresh clone). */
function stubRoutes(routes: Array<[string, Response]>) {
  const mock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : String(input);
    const match = routes.find(([route]) => route === `GET ${url}`);
    if (!match) throw new Error(`no mock route for GET ${url}`);
    return match[1].clone();
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Dashboard", () => {
  it("sieves through the SLIM route (status=active, page_size=500) and links the rows", async () => {
    const mock = stubRoutes([
      [
        "GET /api/v1/certificates/statistics",
        jsonResponse(200, { active: 1, revoked: 0, expiring_soon: 1 }),
      ],
      [SLIM_ROUTE, jsonResponse(200, SLIM_ROWS)],
    ]);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    expect(await screen.findByText("CN=soonest.example")).toBeTruthy();
    const requested = mock.mock.calls.map((call) => String(call[0]));
    expect(requested).toContain("/api/v1/certificates/slim?status=active&page_size=500");
    // …and the FULL list route is never touched by the sieve.
    expect(
      requested.every((path) => !path.startsWith("/api/v1/certificates?")),
    ).toBe(true);
    const link = screen.getByRole("link", { name: "CN=soonest.example" });
    expect(link.getAttribute("href")).toBe(
      "/certificates/55555555-5555-4555-8555-000000000005",
    );
    // The slim fields carry no profile label, so the sieve's table shows
    // no Profile column; the incompleteness note is a full-page concern —
    // absent on a single-row page.
    expect(screen.queryByRole("columnheader", { name: "Profile" })).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();
    expect(screen.getByRole("link", { name: "Browse certificates" })).toBeTruthy();
  });

  it("keeps the role=note incompleteness warning when the slim page comes back FULL", async () => {
    const full = Array.from({ length: 500 }, (_, index) => ({
      id: `55555555-5555-4555-8555-${String(index).padStart(12, "0")}`,
      subject: `CN=full-${index}.example`,
      serial_hex: "aa55",
      not_after: SOON_ISO,
      status: "active",
    }));
    stubRoutes([
      [
        "GET /api/v1/certificates/statistics",
        jsonResponse(200, { active: 501, revoked: 0, expiring_soon: 500 }),
      ],
      [SLIM_ROUTE, jsonResponse(200, full)],
    ]);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    await screen.findByText("CN=full-0.example");
    expect(screen.getByRole("note")).toBeTruthy();
  });
});