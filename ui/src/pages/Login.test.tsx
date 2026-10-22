// The Login page's smoke test (the ONE component render test Task 14
// commits to): the TOTP field is hidden until the session store flips
// `mfaRequired` (a `mfa_required` 401 from the relay), then it shows; the
// SSO button follows the relayed config flag; a wrong-credentials message
// surfaces verbatim.

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { SessionProvider } from "../lib/auth";
import Login from "./Login";

function jsonResponse(status: number, body: unknown, contentType = "application/json") {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, { status, headers: { "content-type": contentType } });
}

const UNAUTHORIZED_ENVELOPE = {
  error: { code: "unauthorized", message: "the login was refused" },
};

/** A fetch mock dispatching on `${method} ${path}` (first match wins). */
function mockFetch(routes: Array<[string, Response]>) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const hit = routes.find(([route]) => route === `${method} ${url}`);
    if (!hit) throw new Error(`no mock route for ${method} ${url}`);
    return hit[1];
  });
}

/** Render the login page against a fetch mock: boot 401s (no session),
 * config per-test, login POST per-test. */
function renderLogin(config: Response, loginResponse?: Response) {
  const routes: Array<[string, Response]> = [
    ["GET /api/v1/me", jsonResponse(401, UNAUTHORIZED_ENVELOPE)],
    ["GET /auth/ui/config", config],
  ];
  if (loginResponse) routes.push(["POST /auth/ui/login", loginResponse]);
  vi.stubGlobal("fetch", mockFetch(routes));
  return render(
    <MemoryRouter initialEntries={["/login"]}>
      <SessionProvider>
        <Login />
      </SessionProvider>
    </MemoryRouter>,
  );
}

async function submitCredentials() {
  fireEvent.change(screen.getByLabelText(/username/i), {
    target: { value: "admin" },
  });
  fireEvent.change(screen.getByLabelText(/^password/i, { exact: false }), {
    target: { value: "correct horse battery staple" },
  });
  await screen.findByRole("button", { name: /^sign in$/i });
  fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Login", () => {
  it("renders the password form with the TOTP field hidden and the SSO button shown when configured", async () => {
    renderLogin(jsonResponse(200, { oidc_configured: true, provider: "keycloak" }));

    // The password form is there…
    await screen.findByLabelText(/username/i);
    expect(screen.getByLabelText(/^password/i)).toBeDefined();
    // …the TOTP field is NOT (the store has not seen mfa_required)…
    expect(screen.queryByLabelText(/one-time code/i)).toBeNull();
    // …and the SSO button names the configured provider.
    const sso = await screen.findByRole("button", { name: /sign in with sso/i });
    expect(sso).toBeDefined();
  });

  it("hides the SSO button when the config says SSO is not configured", async () => {
    renderLogin(jsonResponse(200, { oidc_configured: false, provider: null }));

    await screen.findByLabelText(/username/i);
    expect(screen.queryByRole("button", { name: /sign in with sso/i })).toBeNull();
  });

  it("shows the TOTP field after a mfa_required answer and completes the login with the code", async () => {
    let loginCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "GET" && url === "/api/v1/me") {
          return jsonResponse(401, UNAUTHORIZED_ENVELOPE);
        }
        if (method === "GET" && url === "/auth/ui/config") {
          return jsonResponse(200, { oidc_configured: false, provider: null });
        }
        if (method === "POST" && url === "/auth/ui/login") {
          const body = JSON.parse(String(init?.body ?? "{}"));
          loginCalls += 1;
          if (body.totp_code === undefined) {
            return jsonResponse(401, {
              error: { code: "mfa_required", message: "a TOTP code is required" },
            });
          }
          return jsonResponse(200, {
            actor_type: "user",
            actor_id: "x",
            tenant_id: "y",
            capabilities: [],
            username: "admin",
            display_name: "Ada",
            role: "admin",
            mfa_enabled: true,
          });
        }
        throw new Error(`no mock route for ${method} ${url}`);
      }),
    );
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <SessionProvider>
          <Routes>
            {/* The success path navigates to "/": a landing route must
                exist for the login page to unmount into. */}
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<div>the shell</div>} />
          </Routes>
        </SessionProvider>
      </MemoryRouter>,
    );

    await screen.findByLabelText(/username/i);
    expect(screen.queryByLabelText(/one-time code/i)).toBeNull();

    // First attempt: the relay answers mfa_required and the field flips on.
    await submitCredentials();
    const totp = await screen.findByLabelText(/one-time code/i);
    expect(totp).toBeDefined();
    // No error banner — a challenge is a step, not a failure.
    expect(screen.queryByRole("alert")).toBeNull();

    // Second attempt with the code: the form leaves the DOM for the shell.
    fireEvent.change(totp, { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await vi.waitFor(() => {
      expect(screen.queryByLabelText(/username/i)).toBeNull();
    });
    expect(loginCalls).toBe(2);
  });

  it("surfaces a wrong-credentials message verbatim", async () => {
    renderLogin(
      jsonResponse(200, { oidc_configured: false, provider: null }),
      jsonResponse(401, UNAUTHORIZED_ENVELOPE),
    );

    await screen.findByLabelText(/username/i);
    await submitCredentials();

    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "the login was refused",
    );
    // The TOTP field stays hidden on a plain refusal.
    expect(screen.queryByLabelText(/one-time code/i)).toBeNull();
  });
});