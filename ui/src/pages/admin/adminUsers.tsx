// The user-management view: the tenant's directory (GET /api/v1/users,
// read_users) with role assignment and activation through the PATCH route
// (manage_users), plus local-account creation (POST). The PATCH body is
// built so it can NEVER degenerate into `{}` — the server 400s "nothing
// to update" on that shape, so an unchanged control simply sends nothing.
// The last-admin guard's 409 ("refusing to remove the last active
// administrator") surfaces VERBATIM: the operator asked, the server
// refused, and the reason is the refusal itself.

import { useEffect, useState, type FormEvent } from "react";

import { ApiError } from "../../lib/api";
import { useAuthState } from "../../lib/auth";
import { hasCapability } from "../../lib/certs";
import {
  USER_ROLES,
  buildUserPatch,
  createUser,
  fetchUsers,
  patchUser,
  type AdminUser,
} from "../../lib/admin";

function toApiError(caught: unknown, fallback: string): ApiError {
  return caught instanceof ApiError
    ? caught
    : new ApiError("transport", caught instanceof Error ? caught.message : fallback, 0);
}

function formatDate(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString() : "—";
}

export default function AdminUsers() {
  const auth = useAuthState();
  const canRead = hasCapability(auth.me?.capabilities, "read_users");
  const canManage = hasCapability(auth.me?.capabilities, "manage_users");

  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [listError, setListError] = useState<ApiError | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  // Local-account creation's one secret field: the password lives in this
  // state ONLY while the operator types it and is cleared the moment the
  // create lands (or fails) — it is never echoed, logged, or kept.
  const [draft, setDraft] = useState({ username: "", display_name: "", email: "", role: "viewer", password: "" });
  const [createError, setCreateError] = useState<ApiError | null>(null);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (!canRead) {
      return;
    }
    let cancelled = false;
    fetchUsers()
      .then((rows) => {
        if (!cancelled) setUsers(rows);
      })
      .catch((caught) => {
        if (!cancelled) {
          setListError(toApiError(caught, "the user list could not be loaded"));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [canRead]);

  if (!canRead) {
    return (
      <section>
        <h2>Users</h2>
        <p className="muted">
          Your account does not hold the read_users capability, so it cannot view the tenant's
          users.
        </p>
      </section>
    );
  }

  const applyPatched = (patched: AdminUser) => {
    setUsers((previous) =>
      previous === null ? previous : previous.map((user) => (user.id === patched.id ? patched : user)),
    );
  };

  const changeRole = async (user: AdminUser, role: string) => {
    setActionError(null);
    setNotice(null);
    const body = buildUserPatch(
      { role: user.role, is_active: user.is_active },
      { role, is_active: null },
    );
    if (body === null) {
      return; // No change — never PATCH an empty body at the server.
    }
    setBusyId(user.id);
    try {
      const patched = await patchUser(user.id, body);
      applyPatched(patched);
      setNotice(`Role of ${user.username} set to ${patched.role}.`);
    } catch (caught) {
      setActionError(toApiError(caught, "the role change could not be sent"));
    } finally {
      setBusyId(null);
    }
  };

  const changeActive = async (user: AdminUser, is_active: boolean) => {
    setActionError(null);
    setNotice(null);
    const body = buildUserPatch(
      { role: user.role, is_active: user.is_active },
      { role: null, is_active },
    );
    if (body === null) {
      return;
    }
    setBusyId(user.id);
    try {
      const patched = await patchUser(user.id, body);
      applyPatched(patched);
      setNotice(`${user.username} ${patched.is_active ? "activated" : "deactivated"}.`);
    } catch (caught) {
      setActionError(toApiError(caught, "the activation change could not be sent"));
    } finally {
      setBusyId(null);
    }
  };

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (creating) {
      return;
    }
    setCreateError(null);
    setActionError(null);
    setNotice(null);
    setCreating(true);
    try {
      const created = await createUser({
        username: draft.username,
        email: draft.email,
        role: draft.role,
        password: draft.password,
        ...(draft.display_name.trim() ? { display_name: draft.display_name.trim() } : {}),
      });
      setDraft({ username: "", display_name: "", email: "", role: "viewer", password: "" });
      setNotice(`User ${created.username} created.`);
      reloadList();
    } catch (caught) {
      setCreateError(toApiError(caught, "the user could not be created"));
      // The password is scrubbed from state on failure too.
      setDraft((previous) => ({ ...previous, password: "" }));
    } finally {
      setCreating(false);
    }
  };

  const reloadList = () => {
    setListError(null);
    fetchUsers()
      .then((rows) => setUsers(rows))
      .catch((caught) => setListError(toApiError(caught, "the user list could not be loaded")));
  };

  return (
    <section>
      <h2>Users</h2>
      <p className="muted">
        Roles carry their capability bundles; the server refuses to remove the last active
        administrator (a 409 that is shown here verbatim when it answers).
      </p>

      {notice && <p className="notice">{notice}</p>}
      {actionError && (
        <p className="error-panel" role="alert">
          {actionError.message}
        </p>
      )}
      {listError && (
        <p className="error-panel" role="alert">
          {listError.message}
        </p>
      )}

      {users === null && !listError && <p className="muted">Loading…</p>}
      {users !== null && users.length === 0 && !listError && (
        <p className="muted">No users exist yet.</p>
      )}

      {users !== null && users.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Role</th>
              <th>Provider</th>
              <th>MFA</th>
              <th>Status</th>
              <th>Last login</th>
              {canManage && <th aria-label="Actions" />}
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className="cert-row">
                <td>{user.username}</td>
                <td>{user.email}</td>
                <td>
                  {canManage ? (
                    <select
                      aria-label={`Role for ${user.username}`}
                      value={user.role}
                      disabled={busyId === user.id}
                      onChange={(event) => void changeRole(user, event.target.value)}
                    >
                      {USER_ROLES.map((role) => (
                        <option key={role} value={role}>
                          {role}
                        </option>
                      ))}
                    </select>
                  ) : (
                    user.role
                  )}
                </td>
                <td>{user.auth_provider}</td>
                <td>{user.mfa_enabled ? "on" : "—"}</td>
                <td>
                  <span className={`status-badge status-${user.is_active ? "active" : "revoked"}`}>
                    {user.is_active ? "active" : "deactivated"}
                  </span>
                </td>
                <td>{formatDate(user.last_login_at)}</td>
                {canManage && (
                  <td>
                    <button
                      type="button"
                      className="secondary"
                      disabled={busyId === user.id}
                      onClick={() => void changeActive(user, !user.is_active)}
                    >
                      {user.is_active ? `Deactivate ${user.username}` : `Activate ${user.username}`}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {canManage && (
        <div className="subpanel">
          <h3>Create a local user</h3>
          {createError && (
            <p className="error-panel" role="alert">
              {createError.message}
            </p>
          )}
          <form onSubmit={onCreate} aria-label="Create user">
            <label htmlFor="user-username">Username</label>
            <input
              id="user-username"
              value={draft.username}
              onChange={(event) => setDraft({ ...draft, username: event.target.value })}
            />

            <label htmlFor="user-display-name">Display name (optional)</label>
            <input
              id="user-display-name"
              value={draft.display_name}
              onChange={(event) => setDraft({ ...draft, display_name: event.target.value })}
            />

            <label htmlFor="user-email">Email</label>
            <input
              id="user-email"
              value={draft.email}
              onChange={(event) => setDraft({ ...draft, email: event.target.value })}
            />

            <label htmlFor="user-role">Role</label>
            <select
              id="user-role"
              value={draft.role}
              onChange={(event) => setDraft({ ...draft, role: event.target.value })}
            >
              {USER_ROLES.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>

            <label htmlFor="user-password">Password</label>
            <input
              id="user-password"
              type="password"
              value={draft.password}
              autoComplete="new-password"
              onChange={(event) => setDraft({ ...draft, password: event.target.value })}
            />

            <div className="dialog-actions">
              <button type="submit" disabled={creating}>
                {creating ? "Creating…" : "Create user"}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}