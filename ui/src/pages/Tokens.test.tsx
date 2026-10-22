// The Tokens page's render states (fix round 1): the copy-once reveal —
// a minted token plaintext renders exactly once and "Done — hide it
// forever" then removes it from the DOM — and the three-way capability
// mask that shows or hides the identity-mint and one-shot-mint sections
// exactly as the wire gates them (manage_api_tokens,
// manage_one_shot_tokens, read_service_identities).

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Tokens from "./Tokens";

// Mutable per test; `vi.hoisted` keeps the reference above the hoisted
// module mock.
const session = vi.hoisted(() => ({
  capabilities: ["read_service_identities"] as string[],
}));

vi.mock("../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "alice", tenant_id: "t", capabilities: session.capabilities },
  }),
}));

const MINTED_TOKEN = "ws_at_plain-text-token";

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A fetch mock dispatching on `${method} ${path}` (first match wins). */
function stubRoutes(routes: Array<[string, Response]>) {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const hit = routes.find(([route]) => route === `${method} ${url}`);
    if (!hit) throw new Error(`no mock route for ${method} ${url}`);
    return hit[1];
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

// Route entries are FACTORIES: a Response body can be read exactly once,
// so every render needs its own instances.
const identityList = (): [string, Response] => [
  "GET /api/v1/service-identities?page_size=50",
  jsonResponse(200, []),
];
const oneShotList = (): [string, Response] => [
  "GET /api/v1/one-shot-tokens?page_size=50",
  jsonResponse(200, []),
];
const mint201 = (): [string, Response] => [
  "POST /api/v1/service-identities",
  jsonResponse(201, {
    id: "11111111-1111-4111-8111-0000000000aa",
    name: "ci-bot",
    description: null,
    capabilities: [],
    token: MINTED_TOKEN,
    created_at: "2026-10-22T10:00:00Z",
  }),
];

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  session.capabilities = ["read_service_identities"];
});

describe("Tokens", () => {
  it("reveals a minted token, and Done hides it forever (gone from the DOM)", async () => {
    session.capabilities = ["read_service_identities", "manage_api_tokens"];
    stubRoutes([
      identityList(),
      mint201(),
    ]);

    render(<Tokens />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ci-bot" } });
    fireEvent.click(screen.getByRole("button", { name: "Mint token" }));

    // The plaintext is on the screen exactly once, under the shown-once
    // notice and beside the copy affordance.
    const revealed = await screen.findAllByText(MINTED_TOKEN);
    expect(revealed).toHaveLength(1);
    expect(screen.getByText(/shown to you ONCE/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Copy token" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Done — hide it forever" }));
    expect(screen.queryByText(MINTED_TOKEN)).toBeNull();
    // The page carries no residual trace — the mint form is usable again.
    expect(screen.getByRole("button", { name: "Mint token" })).toBeTruthy();
  });

  it("shows the identity-mint section behind manage_api_tokens, without the one-shot section", () => {
    session.capabilities = ["read_service_identities", "manage_api_tokens"];
    stubRoutes([identityList()]);
    render(<Tokens />);

    expect(screen.getByRole("heading", { name: "Mint an API token" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Mint a one-shot token" })).toBeNull();
  });

  it("shows the one-shot-mint section behind manage_one_shot_tokens, without the identity form", () => {
    session.capabilities = ["read_service_identities", "manage_one_shot_tokens"];
    stubRoutes([oneShotList()]);
    render(<Tokens />);

    expect(screen.getByRole("heading", { name: "Mint a one-shot token" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Mint an API token" })).toBeNull();
    expect(screen.queryByLabelText("Name")).toBeNull();
  });

  it("behind read_service_identities alone, shows both lists and NEITHER mint form", async () => {
    session.capabilities = ["read_service_identities"];
    stubRoutes([identityList(), oneShotList()]);
    render(<Tokens />);

    // The empty states arrive with the list fetches.
    expect(await screen.findByText("No service identities exist yet.")).toBeTruthy();
    expect(await screen.findByText("No one-shot tokens have been minted yet.")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Mint an API token" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Mint a one-shot token" })).toBeNull();
  });

  it("says so plainly when none of the three capabilities is held", () => {
    session.capabilities = [];
    stubRoutes([]);
    render(<Tokens />);

    expect(screen.getByText(/none of read_service_identities/)).toBeTruthy();
  });
});