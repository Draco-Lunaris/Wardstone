// The apiFetch contract (Task 14, TDD-first):
//
// 1. `X-Requested-With: wardstone-ui` is injected on every mutating
//    request (POST/PUT/PATCH/DELETE) and NEVER on GET/HEAD — the CSRF
//    marker the ws-web proxy's rule demands on cookie-carrying mutations.
// 2. ws-api's JSON error envelope `{"error":{"code","message"}}` parses
//    into `ApiError { code, message, status }` exactly.
// 3. The 429 bodies tower_governor emits are PLAIN TEXT
//    (`Too Many Requests! Wait for Ns` — NOT the JSON envelope; Plan 3
//    Task 13 verified the wire shape): a non-JSON error body parses into
//    an ApiError with a sane message and status 429.
// 4. A JSON success body parses as T; a 204 with an empty body does not
//    blow up on a json() read.

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiFetch } from "./api";

function jsonResponse(
  status: number,
  body: string,
  contentType = "application/json",
): Response {
  return new Response(body, {
    status,
    headers: { "content-type": contentType },
  });
}

/** Await a call that MUST fail, and return the ApiError it threw. */
async function apiErrorOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("the call unexpectedly succeeded");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch header injection", () => {
  it("injects X-Requested-With on POST, PUT, PATCH, and DELETE", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(200, "{}"),
    );
    vi.stubGlobal("fetch", fetchMock);

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      await apiFetch("/api/v1/whatever", { method });
      const init = fetchMock.mock.calls.at(-1)?.[1] as RequestInit;
      const headers = new Headers(init.headers);
      expect(headers.get("x-requested-with")).toBe("wardstone-ui");
    }
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("does not inject the header on the default (GET) request", async () => {
    // The default method is GET: the rule is purely method-driven.
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(200, "{}"),
    );
    vi.stubGlobal("fetch", fetchMock);

    await apiFetch("/api/v1/whatever");
    const [, init] = fetchMock.mock.calls.at(-1)!;
    const headers = new Headers((init as RequestInit).headers);
    expect(headers.get("x-requested-with")).toBeNull();
  });

  it("never injects X-Requested-With on GET or HEAD", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse(200, "{}"),
    );
    vi.stubGlobal("fetch", fetchMock);

    await apiFetch("/api/v1/whatever");
    await apiFetch("/api/v1/whatever", { method: "GET" });
    await apiFetch("/api/v1/whatever", { method: "HEAD" });

    for (const [, init] of fetchMock.mock.calls) {
      const headers = new Headers((init as RequestInit).headers);
      expect(headers.get("x-requested-with")).toBeNull();
    }
  });
});

describe("apiFetch error parsing", () => {
  it("parses the ws-api JSON error envelope into ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          400,
          JSON.stringify({
            error: { code: "bad_request", message: "the name was empty" },
          }),
        ),
      ),
    );

    const err = await apiErrorOf(apiFetch("/api/v1/whatever"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("bad_request");
    expect(err.message).toBe("the name was empty");
    expect(err.status).toBe(400);
  });

  it("parses the mfa_required 401 envelope (the TOTP-step signal)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          401,
          JSON.stringify({
            error: { code: "mfa_required", message: "a TOTP code is required" },
          }),
        ),
      ),
    );

    const err = await apiErrorOf(apiFetch("/api/v1/whatever"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.code).toBe("mfa_required");
    expect(err.status).toBe(401);
  });

  it("parses a non-JSON 429 tower_governor body with a sane message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          429,
          "Too Many Requests! Wait for 3s",
          "text/plain; charset=utf-8",
        ),
      ),
    );

    const err = await apiErrorOf(apiFetch("/api/v1/whatever"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(429);
    expect(err.code).toBe("rate_limited");
    expect(err.message).toContain("3s");
    expect(err.message).toContain("Too Many Requests");
  });

  it("survives a non-JSON error body that is not 429 too", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(500, "the world broke", "text/html"),
      ),
    );

    const err = await apiErrorOf(apiFetch("/api/v1/whatever"));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(500);
    expect(err.code).toBe("http_500");
    expect(err.message).toContain("the world broke");
  });

  it("throws ApiError with the envelope message for a ws-web relayed error", async () => {
    // The relay passes ws-api error bodies through verbatim; the login
    // page surfaces the message as-is.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          401,
          JSON.stringify({
            error: { code: "unauthorized", message: "the password was wrong" },
          }),
        ),
      ),
    );

    const err = await apiErrorOf(
      apiFetch("/auth/ui/login", {
        method: "POST",
        body: JSON.stringify({ username: "u", password: "p" }),
      }),
    );
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toBe("the password was wrong");
    expect(err.code).toBe("unauthorized");
  });
});

describe("apiFetch success parsing", () => {
  it("returns the parsed JSON body on success", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          200,
          JSON.stringify({
            actor_type: "user",
            username: "admin",
            capabilities: ["manage_system"],
          }),
        ),
      ),
    );

    const me = await apiFetch<{ username: string }>("/api/v1/me");
    expect(me.username).toBe("admin");
  });

  it("returns undefined-ish for a 204 with an empty body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 204 })),
    );

    const result = await apiFetch<undefined>("/auth/ui/logout", {
      method: "POST",
    });
    expect(result).toBeUndefined();
  });
});