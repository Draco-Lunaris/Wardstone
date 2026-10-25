// The admin section's wrapper: four tabs (SSO provider, profiles, users,
// master passphrase) gated section-level on the capabilities each tab's
// routes demand — and the passphrase tab additionally on
// `me.sealed_volume`, since a plaintext legacy volume has no
// passphrase to change. The server is the real boundary everywhere —
// this gating only hides what would 403, per the Shell's Task 15
// polish lesson.

import { useState } from "react";

import { useAuthState } from "../../lib/auth";
import { hasCapability } from "../../lib/certs";
import AdminProfiles from "./adminProfiles";
import AdminUsers from "./adminUsers";
import MasterPassphrase from "./MasterPassphrase";
import OidcConfig from "./OidcConfig";

type TabKey = "oidc" | "profiles" | "users" | "passphrase";

/** `sealed: true` names the one tab that additionally requires
 * `me.sealed_volume` — the master-passphrase change form exists only on
 * a volume that actually serves unlocked-from-envelopes. */
const TABS: Array<{
  key: TabKey;
  label: string;
  caps: string[];
  sealed?: boolean;
}> = [
  { key: "oidc", label: "SSO provider (OIDC)", caps: ["manage_system"] },
  { key: "profiles", label: "Profiles", caps: ["read_profiles", "manage_profiles"] },
  { key: "users", label: "Users", caps: ["read_users", "manage_users"] },
  { key: "passphrase", label: "Master passphrase", caps: ["manage_system"], sealed: true },
];

export default function Admin() {
  const auth = useAuthState();
  const [tabKey, setTabKey] = useState<TabKey | null>(null);

  const visible = TABS.filter(
    (tab) =>
      tab.caps.some((capability) => hasCapability(auth.me?.capabilities, capability)) &&
      (!tab.sealed || auth.me?.sealed_volume === true),
  );
  const active = visible.find((tab) => tab.key === tabKey) ?? visible[0];

  if (!active) {
    return (
      <main className="page-view">
        <div className="page-header">
          <h1>Admin</h1>
        </div>
        <p className="muted">
          Admin needs one of manage_system, read_profiles, manage_profiles, read_users, or
          manage_users — your account holds none of them, so there is nothing to show here.
        </p>
      </main>
    );
  }

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Admin</h1>
      </div>
      <div className="tabs" role="tablist" aria-label="Admin sections">
        {visible.map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={tab.key === active.key}
            className={tab.key === active.key ? "active" : undefined}
            onClick={() => setTabKey(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {active.key === "oidc" && <OidcConfig />}
      {active.key === "profiles" && <AdminProfiles />}
      {active.key === "users" && <AdminUsers />}
      {active.key === "passphrase" && <MasterPassphrase />}
    </main>
  );
}