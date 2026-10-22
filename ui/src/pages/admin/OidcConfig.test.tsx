// The OIDC form's secret handling, on the rendered page: a first
// configuration REQUIRES the secret (client-side, the server's 400
// wording) and PUTs it verbatim; an existing configuration with
// client_secret_set shows only that a secret is stored (placeholder
// "keep existing", never the secret itself) and its unchanged save maps
// client_secret to the ABSENT key; and the test button always sends a
// well-formed override (Task 5's T5-M1: a malformed override would be
// read as "no override" and probe the saved configuration).

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import OidcConfig from "./OidcConfig";

const session = vi.hoisted(() => ({
  capabilities: ["manage_system"] as string[],
}));

vi.mock("../../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: { actor_id: "alice", tenant_id: "t", capabilities: session.capabilities },
  }),
}));

const EXISTING_CONFIG = {
  provider_type: "keycloak",
  display_name: "IdP",
  discovery_url: "https://idp.example.test/.well-known/openid-configuration",
  client_id: "wardstone-ui",
  redirect_uri: "https://wardstone.example.test/auth/ui/oidc/keycloak/callback",
  scopes: "openid profile email",
  client_secret_set: true,
};

const CREATED_CONFIG = { ...EXISTING_CONFIG, client_secret_set: true };

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A fetch mock dispatching on `${method} ${path}`, recording bodies.
 * When SEVERAL entries share a route key, the nth match answers the nth
 * request for that key (staying on the last one) — so sequential
 * state-changing responses can be stubbed in order. Each request gets a
 * fresh CLONE of the stored entry: a Response body can be read once, and
 * the same route can be hit twice (two saves, two probes). */
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

function fillNewConfigForm() {
  fireEvent.change(screen.getByLabelText("Provider type"), { target: { value: "azure" } });
  fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "Work SSO" } });
  fireEvent.change(screen.getByLabelText("Discovery URL"), {
    target: { value: "https://login.example.test/.well-known/openid-configuration" },
  });
  fireEvent.change(screen.getByLabelText("Client ID"), { target: { value: "wardstone" } });
  fireEvent.change(screen.getByLabelText("Client secret"), { target: { value: "hunt3r2" } });
  fireEvent.change(screen.getByLabelText(/Redirect URI/), {
    target: { value: "https://wardstone.example.test/auth/ui/oidc/azure/callback" },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  session.capabilities = ["manage_system"];
});

describe("OidcConfig", () => {
  it("on a first configuration, refuses to save without a secret and PUTs the typed one", async () => {
    const { mock, bodies } = stubRoutes([
      ["GET /api/v1/oidc/config", jsonResponse(404, { error: { code: "not_found", message: "no OIDC provider configuration exists" } })],
      ["PUT /api/v1/oidc/config", jsonResponse(200, CREATED_CONFIG)],
    ]);

    render(<OidcConfig />);
    expect(await screen.findByText(/No provider is configured/)).toBeTruthy();
    expect(
      (screen.getByLabelText("Client secret") as HTMLInputElement).placeholder,
    ).toContain("Required for a new configuration");

    // Fill everything EXCEPT the secret: the client-side refusal fires
    // with the server's own wording, and no request leaves the page.
    fireEvent.change(screen.getByLabelText("Provider type"), { target: { value: "azure" } });
    fireEvent.change(screen.getByLabelText(/Redirect URI/), {
      target: { value: "https://wardstone.example.test/auth/ui/oidc/azure/callback" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    expect(await screen.findByText("client_secret is required when first configuring the provider")).toBeTruthy();
    expect(mock).toHaveBeenCalledTimes(1); // Only the GET happened.

    // Now with a secret typed: the PUT carries it, plus everything else.
    fillNewConfigForm();
    fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    await screen.findByText("Saved the provider configuration.");
    const put = bodies.at(-1) ? JSON.parse(bodies.at(-1)!) : null;
    expect(put.provider_type).toBe("azure");
    expect(put.client_secret).toBe("hunt3r2");
    expect("client_secret_set" in put).toBe(false);
  });

  it("on an existing configuration, never echoes the stored secret and omits an unchanged one from the PUT", async () => {
    const { bodies } = stubRoutes([
      ["GET /api/v1/oidc/config", jsonResponse(200, EXISTING_CONFIG)],
      ["PUT /api/v1/oidc/config", jsonResponse(200, EXISTING_CONFIG)],
    ]);

    render(<OidcConfig />);
    expect(await screen.findByText(/stored secret is never displayed/)).toBeTruthy();
    const secretInput = screen.getByLabelText("Client secret") as HTMLInputElement;
    expect(secretInput.value).toBe("");
    expect(secretInput.placeholder).toContain("keep existing");

    // Save WITHOUT touching the secret: client_secret is absent from the
    // body (the server keeps what it stored) — never null, never "".
    fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    await screen.findByText("Saved the provider configuration.");
    const put = bodies.at(-1) ? JSON.parse(bodies.at(-1)!) : null;
    expect("client_secret" in put).toBe(false);

    // Typing one rotates it.
    fireEvent.change(secretInput, { target: { value: "rotated" } });
    fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    await screen.findByText("Saved the provider configuration.");
    expect(JSON.parse(bodies.at(-1)!).client_secret).toBe("rotated");
  });

  it("refuses a non-https redirect_uri client-side before any request", async () => {
    const { mock } = stubRoutes([
      ["GET /api/v1/oidc/config", jsonResponse(200, EXISTING_CONFIG)],
    ]);

    render(<OidcConfig />);
    expect(await screen.findByLabelText("Client ID")).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/Redirect URI/), {
      target: { value: "http://wardstone.example.test/auth/ui/oidc/keycloak/callback" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));

    expect(screen.getByText("redirect_uri must be an https URL")).toBeTruthy();
    expect(mock).toHaveBeenCalledTimes(1); // The GET only; no PUT left the page.
  });

  it("sends a well-formed override on Test discovery and shows the answer", async () => {
    const { bodies } = stubRoutes([
      ["GET /api/v1/oidc/config", jsonResponse(200, EXISTING_CONFIG)],
      [
        "POST /api/v1/oidc/config/test",
        jsonResponse(200, {
          issuer: "https://idp.example.test/realms/main",
          authorization_endpoint: "https://idp.example.test/realms/main/protocol/openid-connect/auth",
          token_endpoint: "https://idp.example.test/realms/main/protocol/openid-connect/token",
          jwks_uri: "https://idp.example.test/realms/main/protocol/openid-connect/certs",
        }),
      ],
    ]);

    render(<OidcConfig />);
    expect(await screen.findByLabelText("Client ID")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Test discovery" }));

    expect(await screen.findByText("Discovery answered")).toBeTruthy();
    expect(screen.getByText("https://idp.example.test/realms/main")).toBeTruthy();
    const posted = bodies.at(-1) ? JSON.parse(bodies.at(-1)!) : null;
    // Well-formed override shape — the fields the probe may consume.
    expect(posted.override.provider_type).toBe("keycloak");
    expect(posted.override.discovery_url).toBe(EXISTING_CONFIG.discovery_url);
    expect(posted.override.redirect_uri).toBe(EXISTING_CONFIG.redirect_uri);
    // Untouched secret field → absent key, never null (T5-M1 soft-failure
    // discipline: the body must parse as an override).
    expect("client_secret" in posted.override).toBe(false);
  });

  it("shows a failed probe's message verbatim", async () => {
    stubRoutes([
      ["GET /api/v1/oidc/config", jsonResponse(200, EXISTING_CONFIG)],
      [
        "POST /api/v1/oidc/config/test",
        jsonResponse(400, {
          error: { code: "bad_request", message: "discovery probe failed: connection refused" },
        }),
      ],
    ]);

    render(<OidcConfig />);
    expect(await screen.findByLabelText("Client ID")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Test discovery" }));

    expect(await screen.findByText("discovery probe failed: connection refused")).toBeTruthy();
  });
});