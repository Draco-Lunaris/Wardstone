// The dashboard: the estate's headline statistics and the "expiring
// soon" list. The statistics route and the certificate list both sit
// behind `read_certificates` — an actor without it gets a plain notice
// (the nav still lands here: it is the home route), never a 403.
//
// The expiring list has no dedicated query axis: it feeds
// `GET /certificates?status=active` into the pure client-side selection
// pinned in lib/stats (`selectExpiringSoon`, the same 30-day horizon the
// server's `expiring_soon` tile counts) and links each row to its detail
// route.

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  fetchCertificates,
  fetchCertificateStatistics,
  hasCapability,
  type Certificate,
  type CertificateStatistics,
} from "../lib/certs";
import { selectExpiringSoon, statCards } from "../lib/stats";

/** One estate page of active certificates to sieve client-side — far
 * past any real 30-day expiry burst. */
const ACTIVE_DASHBOARD_PAGE = 100;

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export default function Dashboard() {
  const auth = useAuthState();
  const canReadCertificates = hasCapability(auth.me?.capabilities, "read_certificates");

  const [stats, setStats] = useState<CertificateStatistics | null>(null);
  const [expiring, setExpiring] = useState<Certificate[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (!canReadCertificates) {
      return;
    }
    let cancelled = false;
    setError(null);
    const statistics = fetchCertificateStatistics();
    const active = fetchCertificates({ status: "active", pageSize: ACTIVE_DASHBOARD_PAGE });
    statistics
      .then((value) => {
        if (!cancelled) setStats(value);
      })
      .catch((caught) => {
        if (!cancelled) setFirstError(caught, setError);
      });
    active
      .then((rows) => {
        if (!cancelled) setExpiring(selectExpiringSoon(rows));
      })
      .catch((caught) => {
        if (!cancelled) setFirstError(caught, setError);
      });
    return () => {
      cancelled = true;
    };
  }, [canReadCertificates]);

  // The first failure wins the error panel; a failed half (stats OR the
  // list) still shows whatever landed.
  function setFirstError(caught: unknown, report: (error: ApiError) => void) {
    report(
      caught instanceof ApiError ? caught : new ApiError("transport", String(caught), 0),
    );
  }

  if (!canReadCertificates) {
    return (
      <main className="page-view">
        <h1>Dashboard</h1>
        <p className="muted">
          Your account does not hold the read_certificates capability, so it cannot view
          certificate statistics or the expiring list.
        </p>
      </main>
    );
  }

  return (
    <main className="page-view">
      <div className="page-header">
        <h1>Dashboard</h1>
        <Link className="button-link" to="/certificates">
          Browse certificates
        </Link>
      </div>

      {stats && (
        <dl className="stat-tiles">
          {statCards(stats).map((card) => (
            <div key={card.key}>
              <dt>{card.label}</dt>
              <dd>{card.value}</dd>
            </div>
          ))}
        </dl>
      )}

      <h2>Expiring within 30 days</h2>
      {error && (
        <p className="error-panel" role="alert">
          {error.message}
        </p>
      )}
      {expiring === null && !error && <p className="muted">Loading…</p>}
      {expiring !== null && expiring.length === 0 && !error && (
        <p className="muted">Nothing expires in the next 30 days.</p>
      )}
      {expiring !== null && expiring.length > 0 && (
        <table className="cert-table">
          <thead>
            <tr>
              <th>Subject</th>
              <th>Profile</th>
              <th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {expiring.map((certificate) => (
              <tr key={certificate.id} className="cert-row">
                <td>
                  <Link to={`/certificates/${certificate.id}`}>{certificate.subject}</Link>
                </td>
                <td>{certificate.profile_name}</td>
                <td>{formatDate(certificate.not_after)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}