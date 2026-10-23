// The ACME lib layer's pins (Plan 4 Task 10, tests first), against the
// REAL wire shapes at crates/ws-api/src/routes/acme.rs, "The UI-facing
// REST projection" (HEAD):
//
// 1. THE ORDERS QUERY BUILDER — the two scope axes are snake_case
//    (`account_id`, `certificate_id`); the shared paging uses `page` /
//    `page_size`; URLSearchParams does the encoding; empty axes are
//    omitted entirely.
// 2. THE IDENTIFIER REDUCTION — the order's `identifiers` array is stored
//    (and answered) VERBATIM by the server, so this layer treats it as
//    untrusted shape: entries that are not `{…, value: string}` are
//    dropped, and a non-array never throws.
// 3. THE FETCHERS — plain GETs on the /api/v1/acme routes (the CSRF
//    marker is GET-exempt) and the deactivate POST carries BOTH the CSRF
//    header and an empty JSON body (the route takes none).
// 4. NO JWS, NO NONCES anywhere in this layer — the machine surface is
//    not the UI's business.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildAcmeOrdersQuery,
  deactivateAcmeAccount,
  fetchAcmeAccount,
  fetchAcmeAccounts,
  fetchAcmeOrders,
  identifierValues,
  type AcmeDeactivateResponse,
} from "./acme";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("buildAcmeOrdersQuery", () => {
  it("emits the snake_case scope axes and the shared paging", () => {
    expect(
      buildAcmeOrdersQuery({
        accountId: "11111111-1111-4111-8111-000000000000",
        page: 0,
        pageSize: 25,
      }),
    ).toBe(
      "account_id=11111111-1111-4111-8111-000000000000&page=0&page_size=25",
    );
    expect(buildAcmeOrdersQuery({ certificateId: "cert" })).toBe(
      "certificate_id=cert",
    );
  });

  it("URLSearchParams-encodes values and omits empty axes", () => {
    expect(
      buildAcmeOrdersQuery({ accountId: "a id&x=2" }),
    ).toBe("account_id=a+id%26x%3D2");
    expect(buildAcmeOrdersQuery({})).toBe("");
  });

  it("never emits both scope axes as an un-scoped listing", () => {
    // Both set is legal for the builder (the server takes whichever comes
    // first), but the PAGE only ever passes one — pinned by the page
    // tests. An empty query is what the page builds when it has neither.
    expect(buildAcmeOrdersQuery({ accountId: "a", certificateId: "c" })).toBe(
      "account_id=a&certificate_id=c",
    );
  });
});

describe("identifierValues", () => {
  it("reduces a well-formed RFC 8555 identifiers array to its values", () => {
    const order = {
      identifiers: [
        { type: "dns", value: "example.com" },
        { type: "dns", value: "*.example.com" },
      ],
    };
    expect(identifierValues(order)).toEqual(["example.com", "*.example.com"]);
  });

  it("drops malformed entries instead of guessing", () => {
    const order = {
      identifiers: [
        { type: "dns", value: "a.test" },
        { value: 42 },
        "junk",
        {},
        { type: "ip", value: "b.test" },
        null,
      ],
    };
    expect(identifierValues(order)).toEqual(["a.test", "b.test"]);
  });

  it("answers an empty list for a non-array shape, never a throw", () => {
    expect(identifierValues({ identifiers: "corrupted" })).toEqual([]);
    expect(identifierValues({ identifiers: null })).toEqual([]);
    expect(identifierValues({ identifiers: undefined })).toEqual([]);
  });
});

describe("the fetchers", () => {
  it("lists accounts at the plain REST route with the shared paging", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return new Response(JSON.stringify([]), { status: 200 });
    }));
    await fetchAcmeAccounts({ page: 2, pageSize: 50 });
    await fetchAcmeAccounts();
    expect(seen).toEqual([
      "/api/v1/acme/accounts?page=2&page_size=50",
      "/api/v1/acme/accounts",
    ]);
  });

  it("fetches the account detail and scopes orders to exactly one axis", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return new Response(JSON.stringify([]), { status: 200 });
    }));
    await fetchAcmeAccount("an/acct id");
    await fetchAcmeOrders({ accountId: "acct" });
    await fetchAcmeOrders({ certificateId: "cert" });
    expect(seen).toEqual([
      "/api/v1/acme/accounts/an%2Facct%20id",
      "/api/v1/acme/orders?account_id=acct",
      "/api/v1/acme/orders?certificate_id=cert",
    ]);
  });

  it("POSTs the deactivation with the CSRF marker and an empty JSON body, echoing the cascade counts", async () => {
    const deactivated: AcmeDeactivateResponse = {
      id: "11111111-1111-4111-8111-000000000000",
      status: "deactivated",
      authorizations_invalidated: 2,
      orders_invalidated: 1,
    };
    const seen: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((value, key) => (headers[key] = value));
      seen.push({
        url: String(input),
        headers,
        body: typeof init?.body === "string" ? init.body : "",
      });
      return new Response(JSON.stringify(deactivated), { status: 200 });
    }));
    const answer = await deactivateAcmeAccount("11111111-1111-4111-8111-000000000000");
    expect(seen).toEqual([
      {
        url: "/api/v1/acme/accounts/11111111-1111-4111-8111-000000000000/deactivate",
        headers: expect.objectContaining({ "x-requested-with": "wardstone-ui" }),
        body: "{}",
      },
    ]);
    expect(answer).toEqual(deactivated);
  });
});