// The master-passphrase change form (crates/ws-api/src/routes/
// master_key.rs): POST /api/v1/master-key {current, next}, gated
// server-side on manage_system and mounted only when `me.sealed_volume`
// says the instance serves unlocked-from-envelopes (Admin.tsx's tab
// gate — a plaintext legacy volume has no passphrase to change).
//
// The repeat field is the form's one safety: a typo'd `next` would
// seal the whole volume under a passphrase the operator never meant,
// and the next unlock would demand they reproduce the typo — so the
// repeat must match before any request leaves. Neither passphrase is
// ever re-displayed: the fields clear on success and stay only on a
// refusal the operator is retrying.

import { useState, type ChangeEvent, type FormEvent } from "react";

import { ApiError, apiFetch } from "../../lib/api";

/** The route's 200 body: the generation the volume now sits at. */
interface MasterKeyChanged {
  generation: number;
}

const BLANK = { current: "", next: "", repeat: "" };

function toApiError(caught: unknown, fallback: string): ApiError {
  return caught instanceof ApiError
    ? caught
    : new ApiError("transport", caught instanceof Error ? caught.message : fallback, 0);
}

export default function MasterPassphrase() {
  const [form, setForm] = useState(BLANK);
  const [formError, setFormError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const set =
    (key: keyof typeof BLANK) =>
    (event: ChangeEvent<HTMLInputElement>) => {
      setForm((previous) => ({ ...previous, [key]: event.target.value }));
    };

  const onChangePassphrase = async (event: FormEvent) => {
    event.preventDefault();
    if (saving) {
      return;
    }
    setFormError(null);
    setApiError(null);
    setNotice(null);
    if (form.current.trim() === "") {
      setFormError("the current passphrase cannot be empty");
      return;
    }
    if (form.next.trim() === "") {
      setFormError("the new passphrase cannot be empty");
      return;
    }
    if (form.next !== form.repeat) {
      setFormError("the repeated new passphrase does not match");
      return;
    }
    setSaving(true);
    try {
      const changed = await apiFetch<MasterKeyChanged>("/api/v1/master-key", {
        method: "POST",
        body: JSON.stringify({ current: form.current, next: form.next }),
      });
      setForm(BLANK);
      setNotice(
        `The master passphrase changed — the volume is now at generation ${changed.generation}. ` +
          "The next unlock needs the new passphrase.",
      );
    } catch (caught) {
      setApiError(toApiError(caught, "the passphrase could not be changed"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section>
      <h2>Master passphrase</h2>
      <p className="muted">
        Changing the master passphrase re-seals every key envelope on the volume under the new
        one. Rotation cadence is yours — change it whenever the old passphrase may have been
        seen. If a change is interrupted, the unlock page offers to finish it.
      </p>

      {notice && <p className="notice">{notice}</p>}
      {apiError && (
        <p className="error-panel" role="alert">
          {apiError.message}
        </p>
      )}
      {formError && (
        <p className="error-panel" role="alert">
          {formError}
        </p>
      )}

      <form onSubmit={onChangePassphrase}>
        <label htmlFor="master-key-current">Current master passphrase</label>
        <input
          id="master-key-current"
          type="password"
          autoComplete="off"
          value={form.current}
          onChange={set("current")}
        />
        <label htmlFor="master-key-next">New master passphrase</label>
        <input
          id="master-key-next"
          type="password"
          autoComplete="off"
          value={form.next}
          onChange={set("next")}
        />
        <label htmlFor="master-key-repeat">Repeat the new passphrase</label>
        <input
          id="master-key-repeat"
          type="password"
          autoComplete="off"
          value={form.repeat}
          onChange={set("repeat")}
        />
        <button type="submit" disabled={saving}>
          Change passphrase
        </button>
      </form>
    </section>
  );
}