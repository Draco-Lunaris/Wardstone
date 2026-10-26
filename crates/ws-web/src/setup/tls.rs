//! The setup TLS: the certificates the UI serves before the unlock — the
//! first-run page's RAM-only mint ([`first_run_certificate`]) and the
//! locked page's sealed ephemeral mint ([`sealed_certificate`]).

use chrono::{Datelike, Utc};
use rand::{rngs::SysRng, TryRng};
use rcgen::{
    date_time_ymd, ExtendedKeyUsagePurpose as RcgensEku, IsCa, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use ws_ca::error::CaError;
use ws_ca::leafkey::{generate_leaf_key, LeafKeyType};
use zeroize::Zeroizing;

/// The placeholder SAN the setup certificate carries when the instance
/// configuration (`WARDSTONE_SERVER_HOSTNAME`) is unset. The setup
/// certificate is generated once, BEFORE the form is filled in, so its
/// SAN can never come from the form — the form's own `server_hostname`
/// field feeds the CA-issued leaf that replaces it at the end of setup.
pub const PLACEHOLDER_SAN: &str = "wardstone-setup.local";

/// The FIRST-RUN certificate (Task 7's boot rule): the same mint as
/// [`sealed_certificate`] (ECDSA P-256, the operator's browser is the
/// consumer, the same pins) but for the boot that found NO
/// `master.envelope` — self-signed and keyed ONLY in RAM (a ws-secmem
/// arena reservation): no keystore open, no master key, no setup slot,
/// no file, no database. The first-run boot writes NOTHING to the keys
/// volume and dials nothing; the setup page echoes the returned
/// SHA-256 fingerprint for the operator's out-of-band check, and the
/// setup commit's TLS reload replaces the certificate in place (the
/// resume contract). The validity window is the setup page's week
/// ([`validity_window`]): the certificate must outlive the operator's
/// completing the form.
pub fn first_run_certificate(san: &str) -> Result<(String, ws_secmem::SecretBuf, String), CaError> {
    let (key_pair, private_key_der) = generate_leaf_key(LeafKeyType::EcdsaP256)?;
    let private_key_der = Zeroizing::new(private_key_der);

    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Wardstone Setup");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![san_type(san)?];
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![RcgensEku::ServerAuth];
    params.serial_number = Some(setup_serial()?);
    let (not_before, not_after) = validity_window();
    params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
    let certificate = params.self_signed(&key_pair)?;
    let fingerprint = hex::encode(Sha256::digest(certificate.der().as_ref()));
    // The private key crosses to the caller in RAM custody only: the
    // arena reservation is the one plaintext copy (the Zeroizing
    // original above dies at this scope's end), so the first-run boot
    // hands it to the listener without any intermediate heap buffer —
    // and without leaving anything on the volume a restart would
    // have to trust.
    let key = ws_secmem::global()
        .and_then(|mem| mem.alloc_copy(&private_key_der))
        .map_err(|e| CaError::Worker(format!("tls: the protected key arena: {e}")))?;
    Ok((certificate.pem(), key, fingerprint))
}

/// The SEALED-MODE certificate: the same mint as
/// [`first_run_certificate`] (ECDSA P-256, the operator's browser is the
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
