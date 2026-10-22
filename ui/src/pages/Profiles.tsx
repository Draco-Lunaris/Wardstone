// The profiles view: READ-ONLY, by design — profile creation and
// revisioning are `manage_profiles` mutations that run through the API
// and audit trail; the day-to-day UI shows operators what each profile
// pins. The list (`GET /profiles`) deliberately does not hydrate
// `current_revision`; expanding a row fetches the single profile and
// shows the current revision's policy.

import { Fragment, useEffect, useState } from "react";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  fetchProfile,
  fetchProfiles,
  hasCapability,
  type Profile,
  type ProfileRevision,
} from "../lib/certs";

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export default function Profiles() {
  const auth = useAuthState();
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Profile | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<ApiError | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchProfiles()
      .then((rows) => {
        if (!cancelled) setProfiles(rows);
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Expanding fetches the SINGLE profile — the only read that hydrates
  // current_revision. Collapsing keeps the fetched detail cached so a
  // re-expand does not re-request.
  const toggle = (id: string) => {
    if (expandedId === id) {
      setExpandedId(null);
      return;
    }
    setExpandedId(id);
    if (detail?.id === id) {
      return;
    }
    setDetailLoading(true);
    setDetailError(null);
    let cancelled = false;
    fetchProfile(id)
      .then((profile) => {
        if (!cancelled) setDetail(profile);
      })
      .catch((caught) => {
        if (!cancelled) {
          setDetailError(
            caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
          );
        }
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
  };

  if (!hasCapability(auth.me?.capabilities, "read_profiles")) {
    return (
      <main className="page-view">
        <h1>Profiles</h1>
        <p className="muted">
          Your account does not hold the read_profiles capability, so it cannot view the
          certificate profiles.
        </p>
      </main>
    );
  }

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Profiles</h1>
      </div>
      <p className="muted">
        Profiles are read-only here — creation and revisioning run through the API under the
        manage_profiles capability, appended as immutable revisions.
      </p>

      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {profiles === null && !error && <p className="muted">Loading…</p>}
      {profiles !== null && profiles.length === 0 && !error && (
        <p className="muted">No profiles exist yet.</p>
      )}

      {profiles !== null && profiles.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th>Created</th>
              <th aria-label="Details" />
            </tr>
          </thead>
          <tbody>
            {profiles.map((profile) => (
              <Fragment key={profile.id}>
                <tr className="cert-row">
                  <td>{profile.name}</td>
                  <td>{profile.description ?? <span className="muted">—</span>}</td>
                  <td>{formatDate(profile.created_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="secondary"
                      aria-expanded={expandedId === profile.id}
                      onClick={() => toggle(profile.id)}
                    >
                      {expandedId === profile.id ? "Hide policy" : "Policy"}
                    </button>
                  </td>
                </tr>
                {expandedId === profile.id && (
                  <tr>
                    <td colSpan={4} className="ca-detail-cell">
                      <ProfileDetails profile={detail} loading={detailLoading} error={detailError} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}

function ProfileDetails({
  profile,
  loading,
  error,
}: {
  profile: Profile | null;
  loading: boolean;
  error: ApiError | null;
}) {
  if (loading) {
    return <p className="muted">Loading policy…</p>;
  }
  if (error) {
    return (
      <p className="error-panel" role="alert">
        {error.message}
      </p>
    );
  }
  const revision: ProfileRevision | null = profile?.current_revision ?? null;
  return (
    <div className="subpanel">
      {revision ? (
        <dl className="detail-grid">
          <dt>Revision</dt>
          <dd>
            #{revision.revision} ({new Date(revision.created_at).toLocaleDateString()})
          </dd>
          <dt>Key type</dt>
          <dd>{revision.key_type}</dd>
          <dt>Lifetime</dt>
          <dd>{revision.lifetime_days} days</dd>
          <dt>Key usages</dt>
          <dd>{revision.key_usages.join(", ")}</dd>
          <dt>Extended key usages</dt>
          <dd>{revision.eku.length > 0 ? revision.eku.join(", ") : "—"}</dd>
          <dt>SAN patterns</dt>
          <dd>{revision.san_patterns.length > 0 ? revision.san_patterns.join(", ") : "—"}</dd>
        </dl>
      ) : (
        <p className="muted">This profile has no current revision.</p>
      )}
    </div>
  );
}