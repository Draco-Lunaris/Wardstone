// The certificates list: headline statistics, the filter row (status
// chips, profile-name and issuer selects, the 300ms-debounced search
// box), and the paged table. A row opens the detail route.
//
// The filters feed `buildCertificateListQuery` (the URLSearchParams
// discipline is pinned in lib tests); paging is client-driven prev/next
// over the server's page/page_size — a page shorter than PAGE_SIZE is
// the last one.

import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  fetchCas,
  fetchCertificates,
  fetchCertificateStatistics,
  fetchProfiles,
  hasCapability,
  type CaSummary,
  type Certificate,
  type CertificateStatistics,
  type Profile,
} from "../lib/certs";

const PAGE_SIZE = 25;
const SEARCH_DEBOUNCE_MS = 300;

/** (wire value, label) pairs; "" is the unfiltered chip. */
const STATUS_AXIS: Array<[string, string]> = [
  ["", "All"],
  ["active", "Active"],
  ["revoked", "Revoked"],
];

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export default function Certificates() {
  const navigate = useNavigate();
  const auth = useAuthState();
  // The issuer filter needs the CA list, and the CA list route is gated
  // by `read_cas` — gate the affordance, don't provoke a 403.
  const canReadCas = hasCapability(auth.me?.capabilities, "read_cas");

  const [stats, setStats] = useState<CertificateStatistics | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [cas, setCas] = useState<CaSummary[]>([]);

  const [status, setStatus] = useState("");
  const [profileFilter, setProfileFilter] = useState("");
  const [caFilter, setCaFilter] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const [rows, setRows] = useState<Certificate[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);

  // The search box is debounced: the typist finishes a thought, THEN the
  // query recomputes (a keystroke storm must not hit ws-api's limiter).
  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchInput), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  // Filter options. The profile filter works by NAME (`?profile=` is the
  // display label, not an id); a failed options fetch only empties the
  // select — the list itself still works.
  useEffect(() => {
    let cancelled = false;
    fetchProfiles()
      .then((list) => {
        if (!cancelled) setProfiles(list);
      })
      .catch(() => {});
    if (canReadCas) {
      fetchCas()
        .then((list) => {
          if (!cancelled) setCas(list);
        })
        .catch(() => {});
    }
    return () => {
      cancelled = true;
    };
  }, [canReadCas]);

  // Headline counts, once: they are a snapshot, not a live feed.
  useEffect(() => {
    let cancelled = false;
    fetchCertificateStatistics()
      .then((value) => {
        if (!cancelled) setStats(value);
      })
      .catch(() => {
        if (!cancelled) setStats(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchCertificates({
      status,
      profile: profileFilter,
      ca: caFilter,
      q: search,
      page,
      pageSize: PAGE_SIZE,
    })
      .then((list) => {
        if (!cancelled) {
          setRows(list);
          setError(null);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setError(
            caught instanceof ApiError
              ? caught
              : new ApiError("transport", String(caught), 0),
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [status, profileFilter, caFilter, search, page]);

  const resetToFirstPage = () => setPage(0);

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Certificates</h1>
        <Link className="button-link" to="/certificates/new">
          Issue a certificate
        </Link>
      </div>

      {stats && (
        <dl className="stat-tiles">
          <div>
            <dt>Active</dt>
            <dd>{stats.active}</dd>
          </div>
          <div>
            <dt>Revoked</dt>
            <dd>{stats.revoked}</dd>
          </div>
          <div>
            <dt>Expiring within 30 days</dt>
            <dd>{stats.expiring_soon}</dd>
          </div>
        </dl>
      )}

      <div className="cert-filters" role="group" aria-label="Certificate filters">
        <div className="chip-row" aria-label="Filter by status">
          {STATUS_AXIS.map(([value, label]) => (
            <button
              key={value || "all"}
              type="button"
              className={`chip${status === value ? " active" : ""}`}
              onClick={() => {
                setStatus(value);
                resetToFirstPage();
              }}
            >
              {label}
            </button>
          ))}
        </div>

        <label>
          Profile
          <select
            value={profileFilter}
            onChange={(event) => {
              setProfileFilter(event.target.value);
              resetToFirstPage();
            }}
          >
            <option value="">All profiles</option>
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.name}>
                {profile.name}
              </option>
            ))}
          </select>
        </label>

        {canReadCas && (
          <label>
            Issuer
            <select
              value={caFilter}
              onChange={(event) => {
                setCaFilter(event.target.value);
                resetToFirstPage();
              }}
            >
              <option value="">All issuers</option>
              {cas.map((ca) => (
                <option key={ca.id} value={ca.id}>
                  {ca.name}
                </option>
              ))}
            </select>
          </label>
        )}

        <label className="search-filter">
          Search
          <input
            type="search"
            aria-label="Search certificates"
            placeholder="subject, serial, or SAN…"
            value={searchInput}
            onChange={(event) => setSearchInput(event.target.value)}
          />
        </label>
      </div>

      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows !== null && rows.length === 0 && !error && (
        <p className="muted">No certificates match the current filters.</p>
      )}

      {rows !== null && rows.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Serial</th>
              <th>Subject</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((cert) => (
              <tr
                key={cert.id}
                className="cert-row"
                onClick={() => navigate(`/certificates/${cert.id}`)}
              >
                <td>
                  <code>{cert.serial_hex}</code>
                </td>
                <td>
                  <Link
                    to={`/certificates/${cert.id}`}
                    onClick={(event) => event.stopPropagation()}
                  >
                    {cert.subject}
                  </Link>
                </td>
                <td>{cert.profile_name}</td>
                <td>
                  <span className={`status-badge status-${cert.status}`}>{cert.status}</span>
                </td>
                <td>{formatDate(cert.not_after)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="page-controls">
        <button
          type="button"
          disabled={page === 0 || loading}
          onClick={() => setPage((current) => Math.max(0, current - 1))}
        >
          Previous
        </button>
        <span className="muted">Page {page + 1}</span>
        <button
          type="button"
          disabled={loading || rows === null || rows.length < PAGE_SIZE}
          onClick={() => setPage((current) => current + 1)}
        >
          Next
        </button>
      </div>
    </main>
  );
}