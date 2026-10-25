// The master-passphrase change form (crates/ws-api/src/routes/
// master_key.rs), on the rendered page: a matching repeat refuses a
// typo'd `next` BEFORE any request leaves (a typo would seal the volume
// under a passphrase the operator never meant), the POST carries the
// pair verbatim, the server's refusal surfaces verbatim and keeps the
// fields (the operator retries), and a success clears every field and
// names the new generation.

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import MasterPassphrase from "./MasterPassphrase";

vi.mock("../../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: {
      actor_id: "admin",
      tenant_id: "t",
      capabilities: ["manage_system"],
      sealed_volume: true,
    },
  }),
}));

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function stubRoutes(routes: Array<[string, Response]>) {
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
    return matches[0][1].clone();
  });
  vi.stubGlobal("fetch", mock);
  return { mock, bodies };
}

function fillForm(current: string, next: string, repeat: string) {
  fireEvent.change(screen.getByLabelText("Current master passphrase"), {
    target: { value: current },
  });
  fireEvent.change(screen.getByLabelText("New master passphrase"), {
    target: { value: next },
  });
  fireEvent.change(screen.getByLabelText("Repeat the new passphrase"), {
    target: { value: repeat },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("MasterPassphrase", () => {
  it("posts the pair verbatim and names the new generation", async () => {
    const { bodies } = stubRoutes([
      ["POST /api/v1/master-key", jsonResponse(200, { generation: 1 })],
    ]);
    render(<MasterPassphrase />);

    fillForm("the-current-master-passphrase", "the-next-master-passphrase", "the-next-master-passphrase");
    fireEvent.click(screen.getByRole("button", { name: "Change passphrase" }));

    await waitFor(() => {
      screen.getByText(/the volume is now at generation 1/i);
    });
    expect(bodies).toEqual([
      JSON.stringify({
        current: "the-current-master-passphrase",
        next: "the-next-master-passphrase",
      }),
    ]);
    // Every field clears on success — the page never re-displays a
    // passphrase it holds.
    const valueOf = (label: string) =>
      (screen.getByLabelText(label) as HTMLInputElement).value;
    expect(valueOf("Current master passphrase")).toBe("");
    expect(valueOf("New master passphrase")).toBe("");
    expect(valueOf("Repeat the new passphrase")).toBe("");
  });

  it("refuses a mismatched repeat before any request leaves", async () => {
    const { mock } = stubRoutes([
      ["POST /api/v1/master-key", jsonResponse(200, { generation: 1 })],
    ]);
    render(<MasterPassphrase />);

    fillForm("the-current", "the-next", "a-different-repeat");
    fireEvent.click(screen.getByRole("button", { name: "Change passphrase" }));

    screen.getByText("the repeated new passphrase does not match");
    expect(mock).not.toHaveBeenCalled();
  });

  it("surfaces the server's wrong-passphrase refusal verbatim and keeps the fields", async () => {
    stubRoutes([
      [
        "POST /api/v1/master-key",
        jsonResponse(400, {
          error: {
            code: "wrong_passphrase",
            message: "the current passphrase did not open the volume",
          },
        }),
      ],
    ]);
    render(<MasterPassphrase />);

    fillForm("a-wrong-current", "the-next", "the-next");
    fireEvent.click(screen.getByRole("button", { name: "Change passphrase" }));

    await waitFor(() => {
      screen.getByText("the current passphrase did not open the volume");
    });
    // The operator retries: the typed fields stay.
    const valueOf = (label: string) =>
      (screen.getByLabelText(label) as HTMLInputElement).value;
    expect(valueOf("Current master passphrase")).toBe("a-wrong-current");
    expect(valueOf("New master passphrase")).toBe("the-next");
  });
});