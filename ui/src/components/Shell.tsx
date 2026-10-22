// The authenticated shell: left navigation over a main pane, a top bar
// with the signed-in identity and the logout button. Plain, boring, and
// entirely real — every element is wired to the session store.
//
// Task 15's review lesson (T15-M2), applied here: nav affordances are
// capability-gated — an actor without a section's read capability never
// sees the link that would 403. This is POLISH, not protection: the
// server gates every route (the pages show their own notices), and the
// route protection itself is unchanged.

import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuthState, useSession } from "../lib/auth";
import { hasCapability } from "../lib/certs";

/** (label, path, required capability) pairs — nav order pinned to the
 * wireframe; `null` means the entry is for every authenticated actor
 * (Dashboard is the home route; the Admin link stays capability-free —
 * the Task 17 admin console gates its tabs section-level inside the page). */
const NAV: Array<[string, string, string | null]> = [
  ["Dashboard", "/", null],
  ["Certificates", "/certificates", "read_certificates"],
  ["Profiles", "/profiles", "read_profiles"],
  ["CAs", "/cas", "read_cas"],
  ["Tokens", "/tokens", "read_service_identities"],
  ["Audit", "/audit", "read_audit"],
  ["Admin", "/admin", null],
];

export default function Shell() {
  const session = useSession();
  const state = useAuthState();
  const navigate = useNavigate();

  // The display name falls back through the identity's user fields to the
  // actor id (machine actors have no display fields).
  const displayName =
    state.me?.display_name ?? state.me?.username ?? state.me?.actor_id ?? "";

  const handleLogout = async () => {
    await session.logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="shell">
      <header className="shell-topbar">
        <span className="shell-brand">Wardstone</span>
        <span className="shell-user">
          <span className="shell-display-name">{displayName}</span>
          <button type="button" className="secondary" onClick={handleLogout}>
            Sign out
          </button>
        </span>
      </header>
      <div className="shell-body">
        <nav className="shell-nav" aria-label="Primary">
          {NAV.filter((entry) => {
            const required = entry[2];
            return required === null || hasCapability(state.me?.capabilities, required);
          }).map(([label, path]) => (
            <NavLink key={path} to={path} end={path === "/"}>
              {label}
            </NavLink>
          ))}
        </nav>
        <main className="shell-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}