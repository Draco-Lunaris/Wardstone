// The profiles admin view: the referenced-profile delete refusal surfaces
// VERBATIM with its context ("history matters in a CA"), a create POSTs
// the builder's body and refreshes the list, and editing locks the name
// (the update route writes a new revision, the name stays).

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import AdminProfiles from "./adminProfiles";

const session = vi.hoisted(() => ({
  capabilities: ["read_profiles", "manage_profiles"] as string[],
}));

vi.mock("../../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "alice", tenant_id: "t", capabilities: session.capabilities },
  }),
}));

const WEB_SERVER = {
  id: "33333333-3333-4333-8333-000000000003",
  tenant_id: "t",
  name: "web-server",
  description: "TLS server certificates (setup-built-in)",
  current_revision: null,
  created_at: "2026-01-01T00:00:00Z",
};

const WEB_SERVER_DETAIL = {
  ...WEB_SERVER,
  current_revision: {
    id: "44444444-4444-4444-8444-000000000004",
    profile_id: WEB_SERVER.id,
    revision: 1,
    name: "web-server",
    key_type: "rsa2048",
    key_usages: ["digital_signature", "key_encipherment"],
    eku: ["server_auth"],
    lifetime_days: 365,
    san_patterns: ["*.test"],
    is_legacy: false,
    actor_id: "setup",
    created_at: "2026-01-01T00:00:00Z",
  },
};

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A fetch mock dispatching on `${method} ${path}`, recording bodies.
 * When SEVERAL entries share a route key, the nth match answers the nth
 * request for that key (staying on the last one) — so the list re-fetch
 * after a create can stub its own response. Each request gets a fresh
 * CLONE: a Response body can be read once. */
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
  session.capabilities = ["read_profiles", "manage_profiles"];
});

describe("AdminProfiles", () => {
  it("surfaces the referenced-profile delete 409 verbatim, with the history context", async () => {
    stubRoutes([
      ["GET /api/v1/profiles", jsonResponse(200, [WEB_SERVER])],
      [
        `DELETE /api/v1/profiles/${WEB_SERVER.id}`,
        jsonResponse(409, {
          error: {
            code: "conflict",
            message: "profile is referenced by certificates and cannot be deleted",
          },
        }),
      ],
    ]);

    render(<AdminProfiles />);
    expect(await screen.findByText("web-server")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Delete web-server" }));
    // Two-step arm: the first click asks.
    expect(screen.getByRole("button", { name: `Confirm delete ${WEB_SERVER.name}` })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: `Confirm delete ${WEB_SERVER.name}` }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("profile is referenced by certificates and cannot be deleted");
    expect(screen.getByText(/History matters in a CA/)).toBeTruthy();
  });

  it("creates a profile through the builder's body and refreshes the list", async () => {
    const { bodies } = stubRoutes([
      ["GET /api/v1/profiles", jsonResponse(200, [WEB_SERVER])],
      ["GET /api/v1/profiles", jsonResponse(200, [WEB_SERVER])],
      ["POST /api/v1/profiles", jsonResponse(201, { ...WEB_SERVER, name: "client-certs" })],
    ]);

    render(<AdminProfiles />);
    expect(await screen.findByText("web-server")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "New profile" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "client-certs" } });
    fireEvent.change(screen.getByLabelText("Lifetime (days)"), { target: { value: "90" } });
    fireEvent.click(screen.getByRole("button", { name: "Create profile" }));

    expect(await screen.findByText("Profile client-certs created.")).toBeTruthy();
    const posted = bodies.find((body) => body.includes("client-certs"));
    expect(posted).toBeTruthy();
    expect(JSON.parse(posted!)).toEqual({
      name: "client-certs",
      key_type: "ecdsa-p256",
      key_usages: ["digital_signature", "key_encipherment"],
      eku: ["server_auth"],
      lifetime_days: 90,
      san_patterns: [],
    });
  });

  it("locks the name while editing and PUTs a name-less revision body", async () => {
    const { bodies } = stubRoutes([
      ["GET /api/v1/profiles", jsonResponse(200, [WEB_SERVER])],
      [`GET /api/v1/profiles/${WEB_SERVER.id}`, jsonResponse(200, WEB_SERVER_DETAIL)],
      [
        `PUT /api/v1/profiles/${WEB_SERVER.id}`,
        jsonResponse(200, WEB_SERVER_DETAIL),
      ],
    ]);

    render(<AdminProfiles />);
    expect(await screen.findByText("web-server")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const nameInput = await screen.findByLabelText("Name") as HTMLInputElement;
    expect((nameInput).disabled).toBe(true);
    expect(nameInput.value).toBe("web-server");

    fireEvent.change(screen.getByLabelText("Lifetime (days)"), { target: { value: "180" } });
    fireEvent.click(screen.getByRole("button", { name: "Save new revision" }));

    expect(await screen.findByText(/Revision #1 saved for web-server/)).toBeTruthy();
    const put = bodies.find((body) => body.includes("lifetime_days"));
    const parsed = JSON.parse(put!);
    expect("name" in parsed).toBe(false); // The update keeps the profile's name.
    expect(parsed.lifetime_days).toBe(180);
    expect(parsed.key_usages).toEqual(["digital_signature", "key_encipherment"]);
  });

  it("shows the no-capability notice without any of the profile capabilities", () => {
    session.capabilities = [];
    stubRoutes([]);
    render(<AdminProfiles />);

    expect(screen.getByText(/does not hold the read_profiles capability/)).toBeTruthy();
  });
});