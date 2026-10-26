//! The setup TLS: the self-signed certificate the UI serves while no CA
//! exists, keyed in the keystore's setup slot (`ca/setup.key`).

use chrono::{Datelike, Utc};
use rand::{rngs::SysRng, TryRng};
use rcgen::{
    date_time_ymd, ExtendedKeyUsagePurpose as RcgensEku, IsCa, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use ws_ca::error::CaError;
use ws_ca::keystore::KeyStore;
use ws_ca::leafkey::{generate_leaf_key, LeafKeyType};
use zeroize::Zeroizing;

/// The placeholder SAN the setup certificate carries when the instance
/// configuration (`WARDSTONE_SERVER_HOSTNAME`) is unset. The setup
/// certificate is generated once, BEFORE the form is filled in, so its
/// SAN can never come from the form — the form's own `server_hostname`
/// field feeds the CA-issued leaf that replaces it at the end of setup.
pub const PLACEHOLDER_SAN: &str = "wardstone-setup.local";

/// Mint the setup certificate for `san` (the configured instance hostname,
/// or [`PLACEHOLDER_SAN`]), store ITS PRIVATE KEY in the keystore's setup
/// slot, and return `(PEM, sha256-fingerprint-hex)`.
///
/// The fingerprint is over the certificate's DER (what the page displays,
/// and what the operator verifies out of band against the certificate the
/// TLS listener hands the browser). The certificate is SELF-SIGNED — the
/// root CA does not exist yet — and minted fresh per call: a new key and
/// serial each time, so two calls yield two different certificates and
/// fingerprints (the plan deliberately does not pin fingerprint stability
/// across calls; the binary calls this once, before the form is filled
/// in, and restarts regenerate once — while setup is still uncompleted).
///
/// The keystore's master key is generated here when absent (`ensure_master_key`
/// generates on a virgin volume), and the setup slot's envelope write
/// requires it (`store_setup_key` is `Corrupt` without one). The setup key
/// counts towards `has_stored_keys`, so a store holding ONLY the setup key
/// never silently gets a fresh master either.
///
/// [TRANSITIONAL — Task 6 removed the SETUP-side callers (the seal-at-
/// creation setup mints every key sealed from the start and never touches
/// the slot); this mint survives on its ONE remaining caller, the
/// first-run branch of the `wardstone ui` boot, until Task 7's D2 boot
/// rewrite replaces it with the ephemeral in-memory shape and deletes it
/// together with the setup-key slot.]
pub fn setup_certificate(keystore: &mut KeyStore, san: &str) -> Result<(String, String), CaError> {
    keystore.ensure_master_key()?;

    // An ECDSA P-256 leaf key. The setup certificate is strictly temporary
    // (replaced by the CA-issued leaf at the end of setup, living only long
    // enough for the operator to complete the form) — but its consumer is
    // the operator's BROWSER, and browsers do not support Ed25519 TLS
    // certificates (curl/openssl do, which hid the gap from server-side
    // probes). P-256 keeps instant generation AND universal browser support.
    let (key_pair, private_key_der) = generate_leaf_key(LeafKeyType::EcdsaP256)?;
    let private_key_der = Zeroizing::new(private_key_der);

    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Wardstone Setup");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![san_type(san)?];
    // An end-entity certificate: explicitly not a CA, serverAuth only,
    // and the usages a TLS server needs (the same pins as the built-in
    // web-server profile's RSA line).
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![RcgensEku::ServerAuth];
    params.serial_number = Some(setup_serial()?);
    // A generous one-week window (midnight-UTC day bounds, one day of
    // clock-skew margin at the front, the house validity shape): the
    // certificate only has to outlive the operator's completing setup.
    let (not_before, not_after) = validity_window();
    params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);

    let certificate = params.self_signed(&key_pair)?;

    // The key lands in the setup slot BEFORE anything is reported, so a
    // returned PEM always implies its key is recoverable after a restart.
    // The envelope replaces any previous setup slot contents (a
    // re-generated setup certificate simply replaces the last one's key;
    // the old certificate is worthless once the browser reloads).
    keystore.store_setup_key(&private_key_der)?;

    let fingerprint = hex::encode(Sha256::digest(certificate.der().as_ref()));
    Ok((certificate.pem(), fingerprint))
}

/// The SEALED-MODE certificate: the same mint as
/// [`setup_certificate`] (ECDSA P-256, the operator's browser is the
/// consumer, the same pins) but EPHEMERAL — no keystore access (the
/// instance is sealed; no key material exists in this process yet), no
/// setup-slot write, and a validity of hours: the certificate lives only
/// long enough for the operator to read the unlock page and enter the
/// master passphrase, after which the TLS reload presents the real leaf.
/// The private key returns as a `ws_secmem::SecretBuf` — born straight
/// into the protected arena (no heap copy, no file; wiped with the arena
/// reservation when the caller drops it). The fingerprint returns for
/// the unlock page's out-of-band hint.
pub fn sealed_certificate(san: &str) -> Result<(String, ws_secmem::SecretBuf, String), CaError> {
    let (key_pair, private_key_der) = generate_leaf_key(LeafKeyType::EcdsaP256)?;
    let private_key_der = Zeroizing::new(private_key_der);

    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Wardstone Sealed");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![san_type(san)?];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![RcgensEku::ServerAuth];
    params.serial_number = Some(setup_serial()?);
    // Hours, not the week the setup page gets: the sealed certificate
    // must only outlive the unlock form.
    let now = Utc::now();
    let not_before = now - chrono::Duration::hours(1);
    let not_after = now + chrono::Duration::hours(12);
    params.not_before = date_time_ymd(
        not_before.year(),
        not_before.month() as u8,
        not_before.day() as u8,
    );
    params.not_after = date_time_ymd(
        not_after.year(),
        not_after.month() as u8,
        not_after.day() as u8,
    );

    let certificate = params.self_signed(&key_pair)?;
    let fingerprint = hex::encode(Sha256::digest(certificate.der().as_ref()));
    // The private key crosses to the caller in RAM custody only: the
    // arena reservation is the one plaintext copy (the Zeroizing
    // original above dies at this scope's end), so the sealed boot can
    // hand it to the listener without any intermediate heap buffer.
    let key = ws_secmem::global()
        .and_then(|mem| mem.alloc_copy(&private_key_der))
        .map_err(|e| CaError::Worker(format!("tls: the protected key arena: {e}")))?;
    Ok((certificate.pem(), key, fingerprint))
}

/// The SAN from `san`: an IP address becomes an `iPAddress`, anything else
/// a DNS name (the ws-api issuance path's convention).
fn san_type(san: &str) -> Result<rcgen::SanType, CaError> {
    Ok(match san.parse::<std::net::IpAddr>() {
        Ok(ip) => rcgen::SanType::IpAddress(ip),
        Err(_) => rcgen::SanType::DnsName(san.try_into()?),
    })
}

/// Fresh 16-byte serial from the OS entropy source — the house refuses
/// rcgen's deterministic default (`ws_ca`'s `new_serial` documents why:
/// a hash-derived serial collides for two certificates sharing a key, and
/// while this key changes per mint, the pattern is pinned per certificate
/// minted anywhere in the workspace). Entropy failure is a typed error,
/// never a panic.
fn setup_serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(std::io::Error::from)?;
    Ok(SerialNumber::from_slice(&bytes))
}

/// The validity window `(not_before, not_after)` as midnight-UTC
/// `(year, month, day)` triples: midnight one day before today (the
/// house's clock-skew margin) to midnight eight days after, so the parsed
/// certificate spans the full week.
fn validity_window() -> ((i32, u8, u8), (i32, u8, u8)) {
    let not_before = Utc::now() - chrono::Duration::days(1);
    let not_after = not_before + chrono::Duration::days(8);
    (ymd(&not_before), ymd(&not_after))
}

/// The UTC calendar date of `dt` as a `(year, month, day)` triple.
fn ymd(dt: &chrono::DateTime<Utc>) -> (i32, u8, u8) {
    (dt.year(), dt.month() as u8, dt.day() as u8)
}

/// # Unit tests
#[cfg(test)]
mod tests {
    use super::{validity_window, PLACEHOLDER_SAN};

    /// The placeholder SAN is a plain DNS name.
    #[test]
    fn test_placeholder_san_is_a_dns_name() {
        assert!(PLACEHOLDER_SAN.parse::<std::net::IpAddr>().is_err());
    }

    /// The setup certificate spans the full pinned week (day-bounded).
    #[test]
    fn test_validity_window_spans_eight_days() {
        let (nb, na) = validity_window();
        let from = chrono::NaiveDate::from_ymd_opt(nb.0, nb.1 as u32, nb.2 as u32)
            .expect("a calendar date");
        let to = chrono::NaiveDate::from_ymd_opt(na.0, na.1 as u32, na.2 as u32)
            .expect("a calendar date");
        assert_eq!((to - from).num_days(), 8);
    }
}
