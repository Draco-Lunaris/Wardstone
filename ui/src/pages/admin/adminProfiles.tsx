// The admin profiles view: create and revise through the immutable
// `POST/PUT /api/v1/profiles` surface, delete through `DELETE`, with the
// 409 surfaced VERBATIM plus its context — a profile referenced by
// certificates (live or revoked, "history matters in a CA") is never
// deleted; the setup-built-in profiles are typically in that state. The
// update route appends a new revision and keeps the profile's name: the
// name field stays locked while editing, because every revision a live
// profile ever had carries that name.
//
// Reads gate on read_profiles, the mutations on manage_profiles — the
// server is the real boundary; the gating here only hides what would 403.

import { useEffect, useState, type FormEvent } from "react";

import { ApiError } from "../../lib/api";
import { useAuthState } from "../../lib/auth";
import { fetchProfile, fetchProfiles, hasCapability, type Profile } from "../../lib/certs";
import {
  PROFILE_EKUS,
  PROFILE_KEY_TYPES,
  PROFILE_KEY_USAGES,
  buildProfilePayload,
  createProfile,
  deleteProfile,
  updateProfile,
} from "../../lib/admin";

/** The form's raw editing state: the SAN patterns stay text until submit
 * (one per line), the lifetime stays text until parsed — the payload
 * builder owns the conversion, so the form never pre-digests. */
interface ProfileDraft {
  name: string;
  description: string;
  key_type: string;
  key_usages: string[];
  eku: string[];
  lifetime_days: string;
  san_text: string;
}

const BLANK_DRAFT: ProfileDraft = {
  name: "",
  description: "",
  key_type: "ecdsa-p256",
  key_usages: ["digital_signature", "key_encipherment"],
  eku: ["server_auth"],
  lifetime_days: "365",
  san_text: "",
};

function toApiError(caught: unknown, fallback: string): ApiError {
  return caught instanceof ApiError
    ? caught
    : new ApiError("transport", caught instanceof Error ? caught.message : fallback, 0);
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** The SAN textarea's raw text, one entry per line, blanks dropped. */
function parseSanText(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function toggle(list: string[], value: string): string[] {
  return list.includes(value)
    ? list.filter((entry) => entry !== value)
    : [...list, value];
}

export default function AdminProfiles() {
  const auth = useAuthState();
  const canRead = hasCapability(auth.me?.capabilities, "read_profiles");
  const canManage = hasCapability(auth.me?.capabilities, "manage_profiles");

  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [listError, setListError] = useState<ApiError | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<ProfileDraft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [armedDeleteId, setArmedDeleteId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (!canRead) {
      return;
    }
    let cancelled = false;
    fetchProfiles()
      .then((rows) => {
        if (!cancelled) setProfiles(rows);
      })
      .catch((caught) => {
        if (!cancelled) {
          setListError(toApiError(caught, "the profile list could not be loaded"));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [canRead]);

  if (!canRead) {
    return (
      <section>
        <h2>Profiles</h2>
        <p className="muted">
          Your account does not hold the read_profiles capability, so it cannot view the
          certificate profiles.
        </p>
      </section>
    );
  }

  const reloadList = () => {
    setListError(null);
    fetchProfiles()
      .then((rows) => setProfiles(rows))
      .catch((caught) => setListError(toApiError(caught, "the profile list could not be loaded")));
  };

  const clearMessages = () => {
    setFormError(null);
    setApiError(null);
    setNotice(null);
    setDeleteError(null);
  };

  const closeDraft = () => {
    setEditingId(null);
    setDraft(null);
    setFormError(null);
  };

  const startCreate = () => {
    clearMessages();
    setArmedDeleteId(null);
    setEditingId(null);
    setDraft(BLANK_DRAFT);
  };

  const startEdit = (profile: Profile) => {
    clearMessages();
    setArmedDeleteId(null);
    setEditingId(profile.id);
    setDraft(null); // The draft fills from the fetched current revision.
    fetchProfile(profile.id)
      .then((detail) => {
        const revision = detail.current_revision;
        setDraft({
          name: detail.name,
          description: detail.description ?? "",
          key_type: revision?.key_type ?? "ecdsa-p256",
          key_usages: revision?.key_usages ?? [],
          eku: revision?.eku ?? [],
          lifetime_days: revision ? String(revision.lifetime_days) : "",
          san_text: revision ? revision.san_patterns.join("\n") : "",
        });
      })
      .catch((caught) => {
        setApiError(toApiError(caught, `the profile ${profile.name} could not be loaded`));
        setEditingId(null);
      });
  };

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (saving || !draft) {
      return;
    }
    clearMessages();
    const editing = editingId !== null;
    const { body, error } = buildProfilePayload(
      {
        name: draft.name,
        description: draft.description,
        key_type: draft.key_type,
        key_usages: draft.key_usages,
        eku: draft.eku,
        lifetime_days: draft.lifetime_days,
        san_patterns: parseSanText(draft.san_text),
      },
      editing,
    );
    if (error || body === null) {
      // The client-side refusal, worded the way the server words its 400s.
      setFormError(error ?? "the form could not be read");
      return;
    }
    setSaving(true);
    try {
      if (editing && editingId !== null) {
        const revised = await updateProfile(editingId, body);
        setNotice(
          `Revision #${revised.current_revision?.revision ?? "?"} saved for ${revised.name}.`,
        );
      } else {
        const created = await createProfile(body);
        setNotice(`Profile ${created.name} created.`);
      }
      closeDraft();
      reloadList();
    } catch (caught) {
      setApiError(toApiError(caught, "the profile could not be saved"));
    } finally {
      setSaving(false);
    }
  };

  const onDelete = async (profile: Profile) => {
    if (armedDeleteId !== profile.id) {
      // Two-step arm: the first click asks, the second commits.
      setArmedDeleteId(profile.id);
      setDeleteError(null);
      setNotice(null);
      return;
    }
    setArmedDeleteId(null);
    setDeleteError(null);
    try {
      await deleteProfile(profile.id);
      setNotice(`Profile ${profile.name} deleted.`);
      reloadList();
    } catch (caught) {
      setDeleteError(toApiError(caught, "the profile could not be deleted"));
    }
  };

  return (
    <section>
      <h2>Profiles</h2>
      <p className="muted">
        Updates append an immutable revision — nothing past policy is rewritten. Deletion is
        refused for any profile certificates still pin (the built-ins typically are).
      </p>

      {notice && <p className="notice">{notice}</p>}
      {apiError && (
        <p className="error-panel" role="alert">
          {apiError.message}
        </p>
      )}
      {deleteError && (
        <>
          <p className="error-panel" role="alert">
            {deleteError.message}
          </p>
          <p className="muted">
            History matters in a CA: an issued certificate — live or revoked — pins the profile
            revision it was made under, so the server never deletes a referenced profile. Write a
            new revision instead.
          </p>
        </>
      )}
      {formError && (
        <p className="error-panel" role="alert">
          {formError}
        </p>
      )}

      {profiles === null && !listError && <p className="muted">Loading…</p>}
      {listError && (
        <p className="error-panel" role="alert">
          {listError.message}
        </p>
      )}
      {profiles !== null && profiles.length === 0 && !listError && (
        <p className="muted">No profiles exist yet.</p>
      )}

      {profiles !== null && profiles.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th>Created</th>
              {canManage && <th aria-label="Actions" />}
            </tr>
          </thead>
          <tbody>
            {profiles.map((profile) => (
              <tr key={profile.id} className="cert-row">
                <td>{profile.name}</td>
                <td>{profile.description ?? <span className="muted">—</span>}</td>
                <td>{formatDate(profile.created_at)}</td>
                {canManage && (
                  <td>
                    <button type="button" className="secondary" onClick={() => startEdit(profile)}>
                      Edit
                    </button>{" "}
                    <button type="button" className="danger" onClick={() => onDelete(profile)}>
                      {armedDeleteId === profile.id
                        ? `Confirm delete ${profile.name}`
                        : `Delete ${profile.name}`}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {canManage && !draft && (
        <p className="detail-actions">
          <button type="button" onClick={startCreate}>
            New profile
          </button>
        </p>
      )}

      {draft && (
        <div className="subpanel">
          <h3>
            {editingId === null
              ? "New profile"
              : `Revise ${profiles?.find((profile) => profile.id === editingId)?.name ?? ""}`}
          </h3>
          <form
            onSubmit={onSubmit}
            aria-label={editingId === null ? "Create profile" : "Revise profile"}
          >
            <label htmlFor="profile-name">Name</label>
            <input
              id="profile-name"
              value={draft.name}
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
              disabled={editingId !== null}
            />
            {editingId !== null && (
              <p className="muted">
                The name is immutable — updating writes a new revision; the name every revision
                carried stays.
              </p>
            )}

            <label htmlFor="profile-description">Description (optional)</label>
            <input
              id="profile-description"
              value={draft.description}
              onChange={(event) => setDraft({ ...draft, description: event.target.value })}
              disabled={editingId !== null}
            />
            {editingId !== null && (
              <p className="muted">
                The profile description is fixed in v1 — it cannot be edited after creation, so
                the edit PUT leaves it out rather than pretending to save it.
              </p>
            )}

            <label htmlFor="profile-key-type">Key type</label>
            <select
              id="profile-key-type"
              value={draft.key_type}
              onChange={(event) => setDraft({ ...draft, key_type: event.target.value })}
            >
              {PROFILE_KEY_TYPES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>

            <fieldset>
              <legend>Key usages (at least one)</legend>
              {PROFILE_KEY_USAGES.map((usage) => (
                <span className="cap-check" key={usage}>
                  <input
                    type="checkbox"
                    id={`profile-ku-${usage}`}
                    checked={draft.key_usages.includes(usage)}
                    onChange={() =>
                      setDraft({ ...draft, key_usages: toggle(draft.key_usages, usage) })
                    }
                  />
                  <label htmlFor={`profile-ku-${usage}`}>{usage}</label>
                </span>
              ))}
            </fieldset>

            <fieldset>
              <legend>Extended key usages (at least one)</legend>
              {PROFILE_EKUS.map((entry) => (
                <span className="cap-check" key={entry}>
                  <input
                    type="checkbox"
                    id={`profile-eku-${entry}`}
                    checked={draft.eku.includes(entry)}
                    onChange={() => setDraft({ ...draft, eku: toggle(draft.eku, entry) })}
                  />
                  <label htmlFor={`profile-eku-${entry}`}>{entry}</label>
                </span>
              ))}
            </fieldset>

            <label htmlFor="profile-lifetime">Lifetime (days)</label>
            <input
              id="profile-lifetime"
              type="number"
              min={1}
              value={draft.lifetime_days}
              onChange={(event) => setDraft({ ...draft, lifetime_days: event.target.value })}
            />

            <label htmlFor="profile-sans">SAN patterns — one per line</label>
            <textarea
              id="profile-sans"
              rows={4}
              value={draft.san_text}
              onChange={(event) => setDraft({ ...draft, san_text: event.target.value })}
              placeholder={"*.example.test\n10.0.0.0/8"}
            />

            <div className="dialog-actions">
              <button type="button" onClick={closeDraft} disabled={saving}>
                Cancel
              </button>
              <button type="submit" disabled={saving}>
                {saving
                  ? "Saving…"
                  : editingId === null
                    ? "Create profile"
                    : "Save new revision"}
              </button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}