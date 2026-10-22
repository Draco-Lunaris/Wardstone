// The users admin view: the PATCH never sends `{}` (an unchanged control
// sends nothing at all), a role change PATCHes exactly the changed field,
// and the last-admin guard's 409 surfaces VERBATIM — the operator asked
// to demote the only active admin and the refusals is the answer they see
// word for word.

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import AdminUsers from "./adminUsers";

const session = vi.hoisted(() => ({
  capabilities: ["read_users", "manage_users"] as string[],
}));

vi.mock("../../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "alice-id", tenant_id: "t", capabilities: session.capabilities },
  }),
}));

const ALICE = {
  id: "11111111-1111-4111-8111-000000000001",
  tenant_id: "t",
  username: "alice",
  display_name: "Alice",
  email: "alice@example.test",
  role: "admin",
  auth_provider: "local",
  mfa_enabled: true,
  is_active: true,
  force_password_reset: false,
  last_login_at: "2026-10-22T08:00:00Z",
  created_at: "2026-01-01T00:00:00Z",
};

const BOB = {
  ...ALICE,
  id: "22222222-2222-4222-8222-000000000002",
  username: "bob",
  email: "bob@example.test",
  role: "issuer",
  mfa_enabled: false,
};

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A fetch mock dispatching on `${method} ${path}`, recording bodies.
 * When SEVERAL entries share a route key, the nth match answers the nth
 * request for that key (staying on the last one) — so the two PATCHes of
 * a deactivation-then-activation test can answer in order. Each request
 * gets a fresh CLONE: a Response body can be read once. */
function stubRoutes(routes: Array<[string, Response]>) {
  const cursors = new Map<string, number>();
  const bodies: string[] = [];
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (init?.body != null) {
      bodies.push(String(init.body));
    }
    const key = `${method} ${url}`;
    const matches = routes.filter(([route]) => route === key);
    if (matches.length === 0) throw new Error(`no mock route for ${key}`);
    const index = cursors.get(key) ?? 0;
    cursors.set(key, Math.min(index + 1, matches.length - 1));
    return matches[index][1].clone();
  });
  vi.stubGlobal("fetch", mock);
  return { mock, bodies };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  session.capabilities = ["read_users", "manage_users"];
});

describe("AdminUsers", () => {
  it("PATCHes exactly the changed role and re-renders the row from the response", async () => {
    const { mock, bodies } = stubRoutes([
      ["GET /api/v1/users", jsonResponse(200, [ALICE, BOB])],
      [
        `PATCH /api/v1/users/${BOB.id}`,
        jsonResponse(200, { ...BOB, role: "viewer" }),
      ],
    ]);

    render(<AdminUsers />);
    expect(await screen.findByText("bob")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Role for bob"), { target: { value: "viewer" } });

    expect(await screen.findByText("Role of bob set to viewer.")).toBeTruthy();
    expect(bodies.at(-1)).toBe('{"role":"viewer"}'); // Never {} — only the change.
    expect((screen.getByLabelText("Role for bob") as HTMLSelectElement).value).toBe("viewer");
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it("surfaces the last-admin guard's 409 verbatim", async () => {
    stubRoutes([
      ["GET /api/v1/users", jsonResponse(200, [ALICE])],
      [
        `PATCH /api/v1/users/${ALICE.id}`,
        jsonResponse(409, {
          error: {
            code: "conflict",
            message: "refusing to remove the last active administrator",
          },
        }),
      ],
    ]);

    render(<AdminUsers />);
    expect(await screen.findByText("alice")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Role for alice"), { target: { value: "viewer" } });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("refusing to remove the last active administrator");
  });

  it("deactivates and re-activates through the PATCH route", async () => {
    const { bodies } = stubRoutes([
      ["GET /api/v1/users", jsonResponse(200, [BOB])],
      [`PATCH /api/v1/users/${BOB.id}`, jsonResponse(200, { ...BOB, is_active: false })],
      [`PATCH /api/v1/users/${BOB.id}`, jsonResponse(200, { ...BOB, is_active: true })],
    ]);

    render(<AdminUsers />);
    expect(await screen.findByText("bob")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Deactivate bob" }));
    expect(await screen.findByText("bob deactivated.")).toBeTruthy();
    expect(bodies.at(-1)).toBe('{"is_active":false}');

    fireEvent.click(screen.getByRole("button", { name: "Activate bob" }));
    expect(await screen.findByText("bob activated.")).toBeTruthy();
    expect(bodies.at(-1)).toBe('{"is_active":true}');
  });

  it("creates a local user and scrubs the password from the form", async () => {
    const { bodies } = stubRoutes([
      ["GET /api/v1/users", jsonResponse(200, [])],
      ["POST /api/v1/users", jsonResponse(201, BOB)],
    ]);

    render(<AdminUsers />);
    expect(await screen.findByText("No users exist yet.")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "bob" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "bob@example.test" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "issuer" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "initial-pass" } });
    fireEvent.click(screen.getByRole("button", { name: "Create user" }));

    expect(await screen.findByText("User bob created.")).toBeTruthy();
    const posted = JSON.parse(bodies.find((body) => body.includes("bob"))!);
    expect(posted.username).toBe("bob");
    expect(posted.password).toBe("initial-pass");
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
  });

  it("gates the controls behind manage_users — reads-only shows plain roles and no buttons", async () => {
    session.capabilities = ["read_users"];
    stubRoutes([["GET /api/v1/users", jsonResponse(200, [ALICE])]]);

    render(<AdminUsers />);
    expect(await screen.findByText("alice")).toBeTruthy();
    expect(screen.queryByLabelText("Role for alice")).toBeNull();
    expect(screen.queryByRole("button", { name: "Deactivate alice" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Create user" })).toBeNull();
  });
});