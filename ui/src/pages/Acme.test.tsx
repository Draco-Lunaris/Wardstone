// The ACME page's render states (Plan 4 Task 10): the capability mask —
// without `read_acme` the page explains itself and fetches NOTHING, the
// deactivate affordance exists only behind `manage_acme_accounts` — the
// accounts table with its status badges and precomputed order counts,
// the per-account orders expansion (identifiers, profile, the issued
// certificate's link), the cascade-warning confirm dialog (a repeated
// POST is harmless — the route is idempotent — but the dialog still
// stands between the click and the wire), and the certificate deep link
// (`?certificate=<id>` resolves and auto-expands the order that issued
// the certificate).

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import Acme from "./Acme";

// Mutable per test; `vi.hoisted` keeps the reference above the hoisted
// module mock.
const session = vi.hoisted(() => ({
  capabilities: ["read_acme", "manage_acme_accounts"] as string[],
}));

vi.mock("../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "op", tenant_id: "t", capabilities: session.capabilities },
  }),
}));

const ACCOUNT_A_ID = "11111111-1111-4111-8111-0000000000aa";
const ACCOUNT_B_ID = "22222222-2222-4222-8222-0000000000bb";

const ACCOUNT_A = {
  id: ACCOUNT_A_ID,
  jwk_thumbprint: "thumb-a",
  status: "valid",
  tos_agreed_at: null,
  contact: "mailto:a@wardstone.test",
  created_at: "2026-10-22T10:00:00Z",
  orders_count: 1,
};
const ACCOUNT_B = {
  id: ACCOUNT_B_ID,
  jwk_thumbprint: "thumb-b",
  status: "deactivated",
  tos_agreed_at: null,
  contact: null,
  created_at: "2026-10-22T11:00:00Z",
  orders_count: 0,
};

const ORDER_OF_A = {
  id: "33333333-3333-4333-8333-0000000000cc",
  account_id: ACCOUNT_A_ID,
  status: "valid",
  profile_name: "web-server",
  identifiers: [{ type: "dns", value: "host.wardstone.test" }],
  certificate_id: "44444444-4444-4444-8444-0000000000dd",
  error: null,
  expires_at: "2026-10-29T10:00:00Z",
  created_at: "2026-10-22T10:05:00Z",
};

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A fetch mock dispatching on `${method} ${path}` with a QUEUE of
 * responses per route (shifting one per call): the deactivate flow reads
 * the accounts list TWICE (before and after the reload) and a Response
 * body can be consumed exactly once. Every call is recorded.
 */
function stubSequences(routes: Array<[string, Array<Response>]>) {
  const calls: Array<{ method: string; url: string; headers: Record<string, string>; body: string }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((value, key) => (headers[key] = value));
      calls.push({
        method,
        url,
        headers,
        body: typeof init?.body === "string" ? init.body : "",
      });
      const hit = routes.find(([route]) => route === `${method} ${url}`);
      if (!hit || hit[1].length === 0) {
        throw new Error(`no mock sequence entry left for ${method} ${url}`);
      }
      return hit[1].shift() as Response;
    }),
  );
  return calls;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  session.capabilities = ["read_acme", "manage_acme_accounts"];
});

describe("Acme", () => {
  it("lists accounts with status badges and their precomputed order counts", async () => {
    session.capabilities = ["read_acme"];
    stubSequences([
      ["GET /api/v1/acme/accounts?page=0&page_size=25", [jsonResponse(200, [ACCOUNT_A, ACCOUNT_B])]],
    ]);

    render(
      <MemoryRouter>
        <Acme />
      </MemoryRouter>,
    );

    const rowA = await screen.findByText("thumb-a");
    expect(rowA.closest("tr")?.textContent).toContain("mailto:a@wardstone.test");
    expect(rowA.closest("tr")?.textContent).toContain("valid");
    expect(rowA.closest("tr")?.textContent).toContain("1");
    const rowB = screen.getByText("thumb-b");
    expect(rowB.closest("tr")?.textContent).toContain("deactivated");
    expect(rowB.closest("tr")?.textContent).toContain("0");
  });

  it("explains itself without read_acme and fetches nothing", () => {
    session.capabilities = [];
    const calls = stubSequences([]);

    render(
      <MemoryRouter>
        <Acme />
      </MemoryRouter>,
    );

    expect(screen.getByText(/read_acme capability/)).toBeTruthy();
    expect(calls).toEqual([]);
  });

  it("expands an account's orders with identities, profile, and the certificate link", async () => {
    session.capabilities = ["read_acme"];
    stubSequences([
      ["GET /api/v1/acme/accounts?page=0&page_size=25", [jsonResponse(200, [ACCOUNT_A])]],
      ["GET /api/v1/acme/orders?account_id=11111111-1111-4111-8111-0000000000aa", [jsonResponse(200, [ORDER_OF_A])]],
    ]);

    render(
      <MemoryRouter>
        <Acme />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Orders of thumb-a" }));
    expect(await screen.findByText("host.wardstone.test")).toBeTruthy();
    expect(screen.getByText("web-server")).toBeTruthy();
    const link = screen.getByRole("link", { name: "View certificate" });
    expect(link.getAttribute("href")).toBe("/certificates/44444444-4444-4444-8444-0000000000dd");
  });

  it("gates the deactivate affordance behind manage_acme_accounts", async () => {
    session.capabilities = ["read_acme"];
    stubSequences([
      ["GET /api/v1/acme/accounts?page=0&page_size=25", [jsonResponse(200, [ACCOUNT_A])]],
    ]);

    render(
      <MemoryRouter>
        <Acme />
      </MemoryRouter>,
    );

    await screen.findByText("thumb-a");
    expect(screen.getByRole("button", { name: "Orders of thumb-a" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Deactivate…" })).toBeNull();
  });

  it("deactivates only through a cascade-warning confirm dialog, then reloads the list", async () => {
    stubSequences([
      ["GET /api/v1/acme/accounts?page=0&page_size=25", [jsonResponse(200, [ACCOUNT_A]), jsonResponse(200, [ACCOUNT_A])]],
      [
        "POST /api/v1/acme/accounts/11111111-1111-4111-8111-0000000000aa/deactivate",
        [
          jsonResponse(200, {
            id: ACCOUNT_A_ID,
            status: "deactivated",
            authorizations_invalidated: 1,
            orders_invalidated: 1,
          }),
        ],
      ],
    ]);

    render(
      <MemoryRouter>
        <Acme />
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Deactivate…" }));

    const dialog = screen.getByRole("dialog", { name: "Deactivate ACME account" });
    expect(dialog.textContent).toContain("one-way");
    expect(dialog.textContent).toContain("pending authorization");
    expect(dialog.textContent).toContain("open order");

    fireEvent.click(screen.getByRole("button", { name: "Deactivate account" }));
    await screen.findByRole("button", { name: "Deactivate…" });

    const deactivate = screen.queryByRole("dialog", { name: "Deactivate ACME account" });
    expect(deactivate).toBeNull();
  });

  it("resolves the certificate deep link and auto-expands the order's account", async () => {
    session.capabilities = ["read_acme"];
    stubSequences([
      ["GET /api/v1/acme/accounts?page=0&page_size=25", [jsonResponse(200, [ACCOUNT_A])]],
      ["GET /api/v1/acme/orders?certificate_id=44444444-4444-4444-8444-0000000000dd", [jsonResponse(200, [ORDER_OF_A])]],
    ]);

    render(
      <MemoryRouter initialEntries={["/acme?certificate=44444444-4444-4444-8444-0000000000dd"]}>
        <Acme />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/Showing the ACME order that issued certificate/)).toBeTruthy();
    // The order pane is already expanded — no Orders click needed — and
    // it was NOT re-fetched by account_id (the certificate lookup seeded
    // it).
    expect(await screen.findByText("host.wardstone.test")).toBeTruthy();
  });
});