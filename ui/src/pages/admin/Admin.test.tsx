// The admin section's master-passphrase tab gate (Task 4b): the tab
// renders only when `me.sealed_volume` says the instance serves
// unlocked-from-envelopes — a plaintext legacy volume has no
// passphrase to change, so its admin section never offers the form.

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import Admin from "./Admin";

const session = vi.hoisted(() => ({
  me: {
    actor_id: "admin",
    tenant_id: "t",
    capabilities: ["manage_system"],
    sealed_volume: true,
  },
}));

vi.mock("../../lib/auth", () => ({
  useAuthState: () => ({
    status: "authenticated",
    me: session.me,
  }),
}));

vi.mock("./adminProfiles", () => ({ default: () => <div data-testid="profiles" /> }));
vi.mock("./adminUsers", () => ({ default: () => <div data-testid="users" /> }));
vi.mock("./OidcConfig", () => ({ default: () => <div data-testid="oidc" /> }));
vi.mock("./MasterPassphrase", () => ({
  default: () => <div data-testid="master-passphrase" />,
}));

beforeEach(() => {
  session.me = {
    actor_id: "admin",
    tenant_id: "t",
    capabilities: ["manage_system"],
    sealed_volume: true,
  };
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Admin master-passphrase gating", () => {
  it("offers the tab on a sealed volume and mounts the form", () => {
    render(<Admin />);

    fireEvent.click(screen.getByRole("tab", { name: "Master passphrase" }));
    screen.getByTestId("master-passphrase");
  });

  it("hides the tab on a legacy plaintext volume", () => {
    session.me = { ...session.me, sealed_volume: false };
    render(<Admin />);

    expect(
      screen.queryByRole("tab", { name: "Master passphrase" }),
    ).toBeNull();
  });
});