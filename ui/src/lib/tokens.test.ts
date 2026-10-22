// The tokens lib layer's pins (Task 16, tests first), against the REAL
// wire shapes at crates/ws-api/src/routes/credentials.rs HEAD:
//
// 1. THE ONE-SHOT MINT BODY is `{ttl_minutes}`, NOT the brief's guessed
//    `ttl_seconds` — `CreateOneShotTokenBody` defaults to 60 minutes and
//    the server bounds the window at ONE_SHOT_MIN_TTL = 1 minute and
//    ONE_SHOT_MAX_TTL = 24 hours (1440 minutes). The client validates the
//    same bounds BEFORE the request (`isValidOneShotTtl`) and refuses to
//    build an out-of-bounds payload.
// 2. THE SERVICE-IDENTITY MINT BODY — name trimmed; empty description
//    OMITTED from the JSON entirely (never `""`); capabilities passed
//    through verbatim (an empty list is legal; the SERVER caps the grant
//    at the creator's own set).
// 3. TOKEN PLAINTEXTS pass through this layer exactly as Task 15's
//    private keys do: the 201 bodies (`ServiceIdentityCreated.token`,
//    `OneShotTokenCreated.token`) flow into the page state for a
//    copy-once display and are never persisted, logged, or sent anywhere
//    else. Revocation is a plain POST (204, idempotent).
// 4. THE LISTS — both `GET /service-identities` and `GET /one-shot-tokens`
//    are paged (`page`/`page_size` snake_case) under the SAME capability
//    (`read_service_identities`); the mint caps differ (`manage_api_tokens`,
//    `manage_one_shot_tokens` — the route doc-comment's three-way split).

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildOneShotPayload,
  buildServiceIdentityPayload,
  createOneShotToken,
  createServiceIdentity,
  fetchOneShotTokens,
  fetchServiceIdentities,
  isValidOneShotTtl,
  ONE_SHOT_TTL_MAX_MINUTES,
  ONE_SHOT_TTL_MIN_MINUTES,
  revokeServiceIdentity,
  type OneShotTokenCreated,
  type ServiceIdentityCreated,
} from "./tokens";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("isValidOneShotTtl", () => {
  it("accepts the full bounded span: 1..=1440 whole minutes", () => {
    expect(ONE_SHOT_TTL_MIN_MINUTES).toBe(1);
    expect(ONE_SHOT_TTL_MAX_MINUTES).toBe(1440);
    expect(isValidOneShotTtl(1)).toBe(true);
    expect(isValidOneShotTtl(60)).toBe(true);
    expect(isValidOneShotTtl(1440)).toBe(true);
  });

  it("refuses out-of-bounds, fractional, and non-numeric values", () => {
    expect(isValidOneShotTtl(0)).toBe(false);
    expect(isValidOneShotTtl(1441)).toBe(false);
    expect(isValidOneShotTtl(60.5)).toBe(false);
    expect(isValidOneShotTtl(Number.NaN)).toBe(false);
    expect(isValidOneShotTtl(Number.POSITIVE_INFINITY)).toBe(false);
  });
});

describe("buildOneShotPayload", () => {
  it("builds `{ttl_minutes}` for a valid window", () => {
    expect(buildOneShotPayload(60)).toEqual({ ttl_minutes: 60 });
    expect(buildOneShotPayload(1)).toEqual({ ttl_minutes: 1 });
  });

  it("returns null (never a payload) for an invalid window", () => {
    expect(buildOneShotPayload(0)).toBeNull();
    expect(buildOneShotPayload(1441)).toBeNull();
    expect(buildOneShotPayload(12.5)).toBeNull();
  });
});

describe("buildServiceIdentityPayload", () => {
  it("trims the name and drops an empty description key entirely", () => {
    expect(buildServiceIdentityPayload("  ci-bot  ", "  ", [])).toEqual({
      name: "ci-bot",
      capabilities: [],
    });
    expect(buildServiceIdentityPayload(" ci-bot ", " runs the nightly ", ["read_cas"])).toEqual({
      name: "ci-bot",
      description: "runs the nightly",
      capabilities: ["read_cas"],
    });
  });
});

describe("the fetchers", () => {
  it("lists both credential kinds paged at GET routes", async () => {
    const pagesSeen: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      pagesSeen.push(String(input));
      return new Response(JSON.stringify([]), { status: 200 });
    }));
    await fetchServiceIdentities({ page: 2, pageSize: 50 });
    await fetchOneShotTokens({});
    expect(pagesSeen).toEqual([
      "/api/v1/service-identities?page=2&page_size=50",
      "/api/v1/one-shot-tokens",
    ]);
  });

  it("POSTs the service-identity mint with the CSRF header and echoes the 201 body", async () => {
    const minted: ServiceIdentityCreated = {
      id: "11111111-1111-4111-8111-0000000000aa",
      name: "ci-bot",
      description: null,
      capabilities: ["read_cas"],
      token: "ws_at_secret",
      created_at: "2026-10-22T10:00:00Z",
    };
    const seen: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((value, key) => (headers[key] = value));
      seen.push({
        url: String(input),
        headers,
        body: String(init?.body ?? ""),
      });
      return new Response(JSON.stringify(minted), { status: 201 });
    }));
    const created = await createServiceIdentity({
      name: "ci-bot",
      capabilities: ["read_cas"],
    });
    expect(created).toEqual(minted);
    expect(seen).toHaveLength(1);
    expect(seen[0].url).toBe("/api/v1/service-identities");
    expect(seen[0].headers["x-requested-with"]).toBe("wardstone-ui");
    expect(JSON.parse(seen[0].body)).toEqual({ name: "ci-bot", capabilities: ["read_cas"] });
  });

  it("POSTs the one-shot mint with `{ttl_minutes}` and returns the copy-once body", async () => {
    const minted: OneShotTokenCreated = {
      id: "22222222-2222-4222-8222-0000000000bb",
      token: "ws_ot_secret",
      expires_at: "2026-10-22T11:00:00Z",
    };
    let body = "";
    vi.stubGlobal("fetch", vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      body = String(init?.body ?? "");
      return new Response(JSON.stringify(minted), { status: 201 });
    }));
    const created = await createOneShotToken(30);
    expect(created).toEqual(minted);
    expect(JSON.parse(body)).toEqual({ ttl_minutes: 30 });
  });

  it("POSTs an idempotent revoke and answers undefined on the 204", async () => {
    let method = "";
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      method = (init?.method ?? "GET").toUpperCase();
      expect(String(input)).toBe(
        "/api/v1/service-identities/33333333-3333-4333-8333-0000000000cc/revoke",
      );
      return new Response(null, { status: 204 });
    }));
    await expect(revokeServiceIdentity("33333333-3333-4333-8333-0000000000cc")).resolves.toBeUndefined();
    expect(method).toBe("POST");
  });
});