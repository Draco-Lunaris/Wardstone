// The session store's contract (Task 14, TDD-first). The store is
// framework-free (`SessionStore` in lib/auth.tsx drives everything; the
// React provider is a thin `useSyncExternalStore` shell over it), so these
// tests stub `fetch` directly — the same boundary api.test.ts pins.
//
// Pinned flows:
// - boot: GET /api/v1/me — 401 → unauthenticated, 200 → authenticated + me.
// - login: idle → submitting → authenticated; the mfa_required envelope
//   flips the TOTP step on (and a retry carries the code); a wrong-
//   credentials envelope is surfaced VERBATIM; submitting clears.
// - logout: always ends unauthenticated (best-effort against a 204 relay).

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "./api";
import { SessionStore, type MeResponse } from "./auth";

const ME: MeResponse = {
  actor_type: "user",
  actor_id: "0b8f9a0e-0000-4000-8000-000000000001",
  tenant_id: "0b8f9a0e-0000-4000-8000-000000000002",
  capabilities: ["manage_system"],
  username: "admin",
  display_name: "Ada Admin",
  role: "admin",
  mfa_enabled: true,
};

const MFA_ENVELOPE = {
  error: { code: "mfa_required", message: "a TOTP code is required" },
};

const UNAUTHORIZED_ENVELOPE = {
  error: { code: "unauthorized", message: "the login was refused" },
};

function jsonResponse(status: number, body: unknown, contentType = "application/json") {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, { status, headers: { "content-type": contentType } });
}

/** A fetch mock dispatching on `${method} ${path}` (first match wins). */
function mockFetch(routes: Array<[string, Response | Promise<Response>]>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const key = `${method} ${url}`;
    const hit = routes.find(([route]) => route === key);
    if (!hit) throw new Error(`no mock route for ${key}`);
    return hit[1];
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("boot", () => {
  it("a 401 from /api/v1/me lands unauthenticated", async () => {
    vi.stubGlobal("fetch", mockFetch([["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)]]));

    const store = new SessionStore();
    await store.bootOnce();

    expect(store.state.status).toBe("unauthenticated");
    expect(store.state.me).toBeNull();
  });

  it("a 200 from /api/v1/me lands authenticated with the MeResponse", async () => {
    vi.stubGlobal("fetch", mockFetch([["GET /api/v1/me", jsonResponse(200, ME)]]));

    const store = new SessionStore();
    await store.bootOnce();

    expect(store.state.status).toBe("authenticated");
    expect(store.state.me).toEqual(ME);
  });

  it("bootOnce boots exactly once across concurrent callers", async () => {
    const fetchMock = vi.fn(async () => jsonResponse(401, UNAUTHORIZED_ENVELOPE));
    vi.stubGlobal("fetch", fetchMock);

    const store = new SessionStore();
    await Promise.all([store.bootOnce(), store.bootOnce(), store.bootOnce()]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(store.state.status).toBe("unauthenticated");
  });
});

describe("login", () => {
  it("flows idle → submitting → authenticated on a 200 MeResponse", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch([
        ["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
        ["POST /auth/ui/login", jsonResponse(200, ME)],
      ]),
    );

    const store = new SessionStore();
    await store.bootOnce();

    // login() sets `submitting` synchronously (before its first await),
    // so the pending call's state is observable immediately.
    const pending = store.login("admin", "correct horse battery staple");
    expect(store.state.loginState).toBe("submitting");
    await pending;

    expect(store.state.status).toBe("authenticated");
    expect(store.state.me).toEqual(ME);
    expect(store.state.loginState).toBe("idle");
    expect(store.state.loginError).toBeNull();
    expect(store.state.mfaRequired).toBe(false);
  });

  it("a mfa_required 401 flips mfaRequired on without an error", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url === "/api/v1/me" && method === "GET") return jsonResponse(401, UNAUTHORIZED_ENVELOPE);
      if (url === "/auth/ui/login" && method === "POST") {
        const body = JSON.parse(String(init?.body ?? "{}"));
        if (body.totp_code === undefined) return jsonResponse(401, MFA_ENVELOPE);
        if (body.totp_code === "654321" && body.username === "admin" && body.password === "staple") {
          return jsonResponse(200, ME);
        }
        return jsonResponse(500, "unexpected login fixture");
      }
      throw new Error(`no mock route for ${method} ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const store = new SessionStore();
    await store.bootOnce();

    await store.login("admin", "staple");

    expect(store.state.status).toBe("unauthenticated");
    expect(store.state.mfaRequired).toBe(true);
    expect(store.state.loginError).toBeNull();
    expect(store.state.loginState).toBe("idle");

    // The retry round-trips the TOTP code in the same body shape.
    await store.login("admin", "staple", "654321");
    expect(store.state.status).toBe("authenticated");
    expect(store.state.mfaRequired).toBe(false);
  });

  it("surfaces a wrong-credentials 401 verbatim", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch([
        ["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
        ["POST /auth/ui/login", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
      ]),
    );

    const store = new SessionStore();
    await store.bootOnce();

    await store.login("admin", "nope");

    expect(store.state.status).toBe("unauthenticated");
    expect(store.state.loginError).toBeInstanceOf(ApiError);
    expect(store.state.loginError!.code).toBe("unauthorized");
    expect(store.state.loginError!.message).toBe("the login was refused");
    expect(store.state.loginError!.status).toBe(401);
    expect(store.state.loginState).toBe("idle");
    expect(store.state.me).toBeNull();
  });

  it("a non-JSON 429 lands as a rate_limited ApiError with its plain text", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch([
        ["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
        [
          "POST /auth/ui/login",
          jsonResponse(429, "Too Many Requests! Wait for 3s", "text/plain; charset=utf-8"),
        ],
      ]),
    );

    const store = new SessionStore();
    await store.bootOnce();

    await store.login("admin", "staple");

    expect(store.state.loginError).toBeInstanceOf(ApiError);
    expect(store.state.loginError!.status).toBe(429);
    expect(store.state.loginError!.code).toBe("rate_limited");
    expect(store.state.loginError!.message).toContain("Wait for 3s");
  });
});

describe("logout", () => {
  it("resets an authenticated session to unauthenticated", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch([
        ["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
        ["POST /auth/ui/login", jsonResponse(200, ME)],
        ["POST /auth/ui/logout", new Response(null, { status: 204 })],
      ]),
    );

    const store = new SessionStore();
    await store.bootOnce();
    await store.login("admin", "correct horse battery staple");
    expect(store.state.status).toBe("authenticated");

    await store.logout();

    expect(store.state.status).toBe("unauthenticated");
    expect(store.state.me).toBeNull();
    expect(store.state.mfaRequired).toBe(false);
    expect(store.state.loginError).toBeNull();
  });

  it("ends unauthenticated even when the logout relay fails", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch([
        ["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
        ["POST /auth/ui/login", jsonResponse(200, ME)],
        ["POST /auth/ui/logout", jsonResponse(500, "the upstream died", "text/plain")],
      ]),
    );

    const store = new SessionStore();
    await store.bootOnce();
    await store.login("admin", "correct horse battery staple");

    await store.logout();

    expect(store.state.status).toBe("unauthenticated");
    expect(store.state.me).toBeNull();
  });
});

describe("auth config and OIDC", () => {
  it("loadAuthConfig stores a configured provider", async () => {
    vi.stubGlobal("fetch", mockFetch([["GET /auth/ui/config", jsonResponse(200, { oidc_configured: true, provider: "keycloak" })]]));

    const store = new SessionStore();
    await store.loadAuthConfig();

    expect(store.state.authConfig).toEqual({ oidc_configured: true, provider: "keycloak" });
  });

  it("loadAuthConfig falls back to not-configured on failure", async () => {
    vi.stubGlobal("fetch", mockFetch([["GET /auth/ui/config", jsonResponse(404, { oidc_configured: false, provider: null })]]));

    const store = new SessionStore();
    await store.loadAuthConfig();

    expect(store.state.authConfig).toEqual({ oidc_configured: false, provider: null });
  });
});