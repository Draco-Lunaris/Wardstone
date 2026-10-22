// The issuance workbench: two tabs behind the two SEPARATE capabilities
// (crates/ws-api/src/routes/certificates.rs gates the route by body
// shape) —
//
//   "Paste a CSR"      — capability `issue`:            body WITH csr_pem
//   "Generate a key"   — capability `generate_leaf_key`: body WITHOUT csr_pem
//
// An actor holding only one sees one tab; holding neither, a plain
// notice — the UI cannot gate the server, but it never presents an
// affordance the server would refuse.
//
// # The generated private key lives in this page's memory ONLY
//
// On the generate path the 201 response carries `private_key_pem`
// exactly once (no read endpoint ever answers with it). It is wrapped
// into a blob for a one-time download and NOTHING else: never written to
// storage, never logged, never sent anywhere. The blob URL is revoked on
// unmount (navigation, logout, tab close) via the cleanup below, and
// `makeOneTimeDownload` refuses to download after the revoke. The page
// says so, plainly, before the operator leaves.

import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { ApiError } from "../lib/api";
import { useAuthState } from "../lib/auth";
import {
  downloadText,
  fetchProfile,
  fetchProfiles,
  hasCapability,
  issueCertificate,
  makeOneTimeDownload,
  parseSans,
  type IssueCertificateBody,
  type IssuedCertificate,
  type OneTimeDownload,
  type ProfileRevision,
} from "../lib/certs";

type TabKey = "csr" | "generate";

export default function Issuance() {
  const auth = useAuthState();
  const canIssue = hasCapability(auth.me?.capabilities, "issue");
  const canGenerate = hasCapability(auth.me?.capabilities, "generate_leaf_key");
  // Default to the first tab the actor may actually use.
  const [tab, setTab] = useState<TabKey>(canIssue ? "csr" : "generate");

  const [profiles, setProfiles] = useState<{ id: string; name: string }[]>([]);
  const [profilesError, setProfilesError] = useState<ApiError | null>(null);
  const [profileId, setProfileId] = useState("");
  const [revision, setRevision] = useState<ProfileRevision | null>(null);

  const [subjectCn, setSubjectCn] = useState("");
  const [sansText, setSansText] = useState("");
  const [csrText, setCsrText] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<IssuedCertificate | null>(null);
  const [keyDownload, setKeyDownload] = useState<OneTimeDownload | null>(null);
  // The ref mirrors the state so the unmount cleanup never reads stale
  // closure state — and so replacement downloads are revoked promptly.
  const keyRef = useRef<OneTimeDownload | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchProfiles()
      .then((list) => {
        if (!cancelled) {
          setProfiles(list.map((profile) => ({ id: profile.id, name: profile.name })));
          setProfilesError(null);
        }
      })
      .catch((caught) => {
        if (!cancelled) {
          setProfilesError(
            caught instanceof ApiError
              ? caught
              : new ApiError("transport", String(caught), 0),
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // The issuance form needs the profile's PINNED policy — but the
  // profiles LIST deliberately does not hydrate current_revision, so the
  // selected profile's detail is fetched here (the single get does).
  useEffect(() => {
    setRevision(null);
    if (!profileId) {
      return;
    }
    let cancelled = false;
    fetchProfile(profileId)
      .then((profile) => {
        if (!cancelled) setRevision(profile.current_revision);
      })
      .catch(() => {
        // Policy display only; the server re-validates everything.
        if (!cancelled) setRevision(null);
      });
    return () => {
      cancelled = true;
    };
  }, [profileId]);

  // The generated key's blob URL dies with this page.
  useEffect(() => {
    return () => {
      keyRef.current?.revoke();
    };
  }, []);

  if (!canIssue && !canGenerate) {
    return (
      <main className="page-view">
        <h1>Issue a certificate</h1>
        <p className="muted">
          Your account holds neither the issue nor the generate_leaf_key capability,
          so it cannot request certificates.
        </p>
      </main>
    );
  }

  const issueReady =
    profileId !== "" && subjectCn.trim() !== "" && parseSans(sansText).length > 0 &&
    (tab === "generate" || csrText.trim() !== "");

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (submitting || !issueReady) {
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    const body: IssueCertificateBody = {
      profile_id: profileId,
      subject_cn: subjectCn.trim(),
      sans: parseSans(sansText),
    };
    if (tab === "csr") {
      body.csr_pem = csrText.trim();
    }
    try {
      const response = await issueCertificate(body);
      setResult(response);
      if (response.private_key_pem) {
        // The one-time key: wrap, expose once, remember to revoke.
        const download = makeOneTimeDownload(
          response.private_key_pem,
          "application/x-pem-file",
          `wardstone-key-${response.serial_hex}.pem`,
        );
        keyRef.current?.revoke();
        keyRef.current = download;
        setKeyDownload(download);
      } else {
        keyRef.current?.revoke();
        keyRef.current = null;
        setKeyDownload(null);
      }
    } catch (caught) {
      setSubmitError(
        caught instanceof ApiError
          ? caught
          : new ApiError("transport", String(caught), 0),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="page-view">
      <h1>Issue a certificate</h1>

      {canIssue && canGenerate && (
        <div className="tabs" role="tablist" aria-label="Issuance method">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "csr"}
            className={tab === "csr" ? "active" : ""}
            onClick={() => setTab("csr")}
          >
            Paste a CSR
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "generate"}
            className={tab === "generate" ? "active" : ""}
            onClick={() => setTab("generate")}
          >
            Generate a key on the server
          </button>
        </div>
      )}

      {(profilesError != null || profiles.length === 0) && !profilesError && (
        <p className="error-panel" role="alert">
          No profiles exist yet — a certificate needs a profile to draw its policy from.
        </p>
      )}
      {profilesError && (
        <p className="error-panel" role="alert">
          {profilesError.message}
        </p>
      )}

      <form onSubmit={onSubmit}>
        <label htmlFor="issue-profile">Profile</label>
        <select
          id="issue-profile"
          value={profileId}
          onChange={(event) => setProfileId(event.target.value)}
        >
          <option value="">Choose a profile…</option>
          {profiles.map((profile) => (
            <option key={profile.id} value={profile.id}>
              {profile.name}
            </option>
          ))}
        </select>
        {revision && (
          <p className="muted profile-policy">
            Pins {revision.key_type}, a {revision.lifetime_days}-day lifetime, SAN
            patterns: {revision.san_patterns.join(", ")}
          </p>
        )}

        <label htmlFor="issue-subject">Common name (CN)</label>
        <input
          id="issue-subject"
          value={subjectCn}
          onChange={(event) => setSubjectCn(event.target.value)}
          placeholder="vpn.example.com"
          required
        />

        <label htmlFor="issue-sans">Subject alternative names — one per line (DNS names or IPs)</label>
        <textarea
          id="issue-sans"
          rows={4}
          value={sansText}
          onChange={(event) => setSansText(event.target.value)}
          placeholder={"vpn.example.com\n10.0.0.5"}
          required
        />

        {tab === "csr" && (
          <>
            <label htmlFor="issue-csr">Certificate signing request (PKCS#10 PEM)</label>
            <textarea
              id="issue-csr"
              rows={8}
              className="mono"
              value={csrText}
              onChange={(event) => setCsrText(event.target.value)}
              placeholder={"-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----"}
              required
            />
          </>
        )}

        {(submitError || profilesError) && (
          <p className="error-panel" role="alert">
            {(submitError ?? profilesError)?.message}
          </p>
        )}

        <button type="submit" className="primary" disabled={submitting || !issueReady}>
          {submitting
            ? "Issuing…"
            : tab === "csr"
              ? "Sign the CSR"
              : "Generate key and certificate"}
        </button>
        {tab === "generate" && (
          <p className="muted">
            The server mints the key for you; the private key is handed back exactly once on
            the result below.
          </p>
        )}
      </form>

      {result && (
        <section className="issue-result" aria-label="Issuance result">
          <h2>Issued — {result.profile_name}</h2>
          {keyDownload && (
            <p className="notice" role="status">
              The private key is shown to you ONCE. Wardstone never stores it: download it
              now — it is gone when you leave this page.
            </p>
          )}
          <dl className="detail-grid">
            <dt>Subject</dt>
            <dd>CN={subjectCn.trim()}</dd>
            <dt>Serial (hex)</dt>
            <dd>
              <code>{result.serial_hex}</code>
            </dd>
            <dt>Profile</dt>
            <dd>{result.profile_name}</dd>
            <dt>Valid from</dt>
            <dd>{new Date(result.not_before).toLocaleString()}</dd>
            <dt>Expires</dt>
            <dd>{new Date(result.not_after).toLocaleString()}</dd>
          </dl>

          <div className="detail-actions">
            <button
              type="button"
              onClick={() =>
                downloadText(
                  result.cert_pem,
                  "application/x-pem-file",
                  `wardstone-cert-${result.serial_hex}.pem`,
                )
              }
            >
              Download certificate PEM
            </button>
            {keyDownload && (
              <button type="button" className="danger" onClick={() => keyDownload.download()}>
                Download private key (PEM)
              </button>
            )}
          </div>

          <label htmlFor="issue-result-pem">Server certificate PEM</label>
          <textarea
            id="issue-result-pem"
            className="mono"
            rows={8}
            readOnly
            value={result.cert_pem}
          />

          <p className="back-link">
            <Link to={`/certificates/${result.certificate_id}`}>
              View this certificate in the estate →
            </Link>
          </p>
        </section>
      )}
    </main>
  );
}