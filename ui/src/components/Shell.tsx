// The authenticated shell: left navigation over a main pane, a top bar
// with the signed-in identity and the logout button. Plain, boring, and
// entirely real — every element is wired to the session store.

import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuthState, useSession } from "../lib/auth";

/** (label, path) pairs, nav order pinned to the wireframe. */
const NAV: Array<[string, string]> = [
  ["Dashboard", "/"],
  ["Certificates", "/certificates"],
  ["Profiles", "/profiles"],
  ["CAs", "/cas"],
  ["Tokens", "/tokens"],
  ["Audit", "/audit"],
  ["Admin", "/admin"],
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
          {NAV.map(([label, path]) => (
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