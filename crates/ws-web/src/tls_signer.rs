//! The arena-backed TLS signer (Task 8): the serving leaf's private key
//! never leaves the protected arena, and every signature is taken by a
//! RustCrypto key that exists ONLY on the stack, for the length of one
//! `sign` call.
//!
//! # The custody contract
//!
//! [`ArenaKey`] holds the leaf's PKCS#8 DER as a ws-secmem reservation
//! (`memfd_secret` pages, wiped on drop, never the heap) and implements
//! `rustls::sign::SigningKey`, so the key the TLS stack signs through IS
//! the arena reservation — there is no `PrivatePkcs8KeyDer` heap copy on
//! the serving path anywhere (the pre-Task-8 config built one per
//! certificate load, and `reload_from_pem` another per reload).
//!
//! Two custody properties are load-bearing:
//!
//! 1. **Per-handshake mirror.** rustls asks for a `Signer` with
//!    `choose_scheme` and holds it for the handshake's length; the trait
//!    hands back a `Box<dyn Signer>` (a `'static` object), so the signer
//!    cannot borrow the canonical reservation through an `Arc`. Instead
//!    every `choose_scheme` allocates a SECOND, per-handshake reservation
//!    in the same arena and copies the DER into it. The mirror is wiped
//!    when the handshake's signer drops; the canonical reservation lives
//!    exactly as long as the [`CertifiedKey`] the [`SwapResolver`] holds.
//!    A full arena fails the HANDSHAKE (`choose_scheme` answers `None`,
//!    fail closed) — never the process, and never the heap.
//! 2. **Per-signature stack construction.** [`ArenaSigner::sign`]
//!    reconstructs the RustCrypto signing key from the mirror's DER on the
//!    stack — `p256`/`p384` `ecdsa::SigningKey`,
//!    `ed25519_dalek::SigningKey`, or `rsa::RsaPrivateKey` under PSS /
//!    PKCS#1 v1.5 per the negotiated scheme — signs, and drops it. All
//!    four key types are `ZeroizeOnDrop`, so the stack copy is wiped the
//!    instant the signature exists: no key lives longer than one
//!    signature, and none is ever on the heap.
//!
//! # The swap is the reload
//!
//! [`SwapResolver`] holds the live [`CertifiedKey`] under an
//! [`ArcSwapOption`]: [`SwapResolver::swap`] publishes a new
//! certificate + key pair for the very NEXT handshake — no re-listen, no
//! restart. The sealed boot's unlock and the setup commit both ride it
//! (the old `reload_from_pem` hot-reload path is gone: the resolver swap
//! IS the reload), and the first-run RAM-only certificate serves through
//! the same resolver until the setup commit swaps it out.
//!
//! [`rustls_server_config`] installs the resolver behind the workspace's
//! `ring` provider (selected explicitly per-config, never a process-wide
//! default — the same pin discipline the crate's other TLS glue
//! documents; `aws-lc-rs` never enters the graph).

use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use pkcs8::DecodePrivateKey as _;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use ws_ca::error::CaError;
use ws_ca::leafkey::LeafKeyType;
use ws_secmem::SecretBuf;

/// The serving leaf's private key in arena custody: the PKCS#8 DER
/// reservation plus the algorithm the certificate's key was minted as.
///
/// The fields are private on purpose: the ONLY reads of `der` are the
/// per-handshake arena mirror ([`ArenaKey::choose_scheme`]) and the
/// per-signature stack constructions inside [`ArenaSigner::sign`] — no
/// caller can copy the reservation out into plain memory, and no `Debug`
/// output can ever print it.
pub struct ArenaKey {
    /// The leaf's PKCS#8 DER, in the protected arena (wiped on drop).
    der: SecretBuf,
    /// The algorithm the leaf's key was minted as — selects the
    /// RustCrypto backend every signature constructs on the stack.
    kind: LeafKeyType,
}

impl ArenaKey {
    /// Take custody of a minted leaf key: the DER reservation moves in,
    /// the algorithm pin rides beside it. The caller's reservation is
    /// consumed, not copied — `ArenaKey` is the single custody of the
    /// serving key.
    pub fn new(der: SecretBuf, kind: LeafKeyType) -> Self {
        ArenaKey { der, kind }
    }
}

impl fmt::Debug for ArenaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `SecretBuf`'s own Debug prints the length only; the kind is
        // public data (it is stored in the certificates row).
        f.debug_struct("ArenaKey")
            .field("der", &self.der)
            .field("kind", &self.kind)
            .finish()
    }
}

impl SigningKey for ArenaKey {
    /// Choose the first scheme the CLIENT offered that this key's
    /// algorithm can produce (client preference — the TLS 1.3 rules),
    /// then mirror the DER into a fresh arena reservation for the
    /// handshake's signer. A full (or uninitialisable) arena answers
    /// `None`: the handshake fails closed, and the key never spills to
    /// the heap to keep the TLS surface up.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = offered
            .iter()
            .copied()
            .find(|scheme| supported_schemes(self.kind).contains(scheme))?;
        let mirror = ws_secmem::global()
            .and_then(|mem| mem.alloc_copy(&self.der))
            .map_err(|err| {
                // `SecMemError`'s messages name protections and sizes,
                // never bytes.
                tracing::error!(
                    error = %err,
                    "the serving key could not be mirrored into the \
                     protected arena; the TLS handshake fails closed"
                );
                err
            })
            .ok()?;
        Some(Box::new(ArenaSigner {
            der: mirror,
            kind: self.kind,
            scheme,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.kind {
            LeafKeyType::Rsa2048 | LeafKeyType::Rsa3072 => SignatureAlgorithm::RSA,
            LeafKeyType::EcdsaP256 | LeafKeyType::EcdsaP384 => SignatureAlgorithm::ECDSA,
            LeafKeyType::Ed25519 => SignatureAlgorithm::ED25519,
        }
    }
}

/// The schemes a leaf kind can sign with, in the server's preference
/// order. The negotiation walks the CLIENT's offered list first (see
/// [`ArenaKey::choose_scheme`]), so this order only breaks ties among
/// equally-preferred client offers — which never happens: the client
/// list is a set.
fn supported_schemes(kind: LeafKeyType) -> &'static [SignatureScheme] {
    match kind {
        LeafKeyType::Rsa2048 | LeafKeyType::Rsa3072 => &[
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
        LeafKeyType::EcdsaP256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
        LeafKeyType::EcdsaP384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
        LeafKeyType::Ed25519 => &[SignatureScheme::ED25519],
    }
}

/// One handshake's signer: the per-handshake arena mirror of the serving
/// key plus the negotiated scheme. Every `sign` constructs the RustCrypto
/// key ON THE STACK from the mirror's DER and drops it — all four
/// backends are `ZeroizeOnDrop`, so nothing outlives the signature.
struct ArenaSigner {
    /// The handshake's own arena reservation (wiped when the handshake's
    /// signer drops — the canonical reservation stays with the
    /// [`CertifiedKey`]).
    der: SecretBuf,
    /// The leaf's algorithm pin.
    kind: LeafKeyType,
    /// The scheme the negotiation chose.
    scheme: SignatureScheme,
}

impl fmt::Debug for ArenaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArenaSigner")
            .field("der", &self.der)
            .field("kind", &self.kind)
            .field("scheme", &self.scheme)
            .finish()
    }
}

impl Signer for ArenaSigner {
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        match self.kind {
            LeafKeyType::EcdsaP256 => sign_ecdsa_p256(&self.der, message),
            LeafKeyType::EcdsaP384 => sign_ecdsa_p384(&self.der, message),
            LeafKeyType::Ed25519 => sign_ed25519(&self.der, message),
            LeafKeyType::Rsa2048 | LeafKeyType::Rsa3072 => {
                sign_rsa(&self.der, self.scheme, message)
            }
        }
    }
}

/// One ECDSA P-256 signature: the stack-built key from the mirror's DER,
/// the DER-encoded signature out (the TLS wire form).
fn sign_ecdsa_p256(der: &[u8], message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
    use p256::ecdsa::signature::Signer as _;

    let key = p256::ecdsa::SigningKey::from_pkcs8_der(der).map_err(|_| {
        rustls::Error::General("tls: the ECDSA P-256 serving key is unusable".to_owned())
    })?;
    // The explicit annotation pins `Signer`'s generic signature type (the
    // core trait's associated type is not otherwise inferrable here).
    let signature: p256::ecdsa::Signature = key.sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// One ECDSA P-384 signature (the P-256 shape on the wider curve).
fn sign_ecdsa_p384(der: &[u8], message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
    use p384::ecdsa::signature::Signer as _;

    let key = p384::ecdsa::SigningKey::from_pkcs8_der(der).map_err(|_| {
        rustls::Error::General("tls: the ECDSA P-384 serving key is unusable".to_owned())
    })?;
    // The explicit annotation pins `Signer`'s generic signature type (the
    // core trait's associated type is not otherwise inferrable here).
    let signature: p384::ecdsa::Signature = key.sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// One Ed25519 signature: the stack-built dalek key, the raw 64-byte
/// signature out.
fn sign_ed25519(der: &[u8], message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
    use ed25519_dalek::Signer as _;

    let key = ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(|_| {
        rustls::Error::General("tls: the Ed25519 serving key is unusable".to_owned())
    })?;
    let signature = key.sign(message);
    // `SignatureBytes` is a plain `[u8; 64]` alias — the raw 64-byte
    // wire form.
    Ok(signature.to_bytes().to_vec())
}

/// One RSA signature: the stack-built private key, PSS or PKCS#1 v1.5
/// padding per the negotiated scheme (the PSS signer takes its salt from
/// the OS entropy source — rsa's `getrandom` feature, see the ws-web dep
/// entry), the raw RSA signature out.
fn sign_rsa(der: &[u8], scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    use sha2::{Sha256, Sha384, Sha512};

    let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|_| rustls::Error::General("tls: the RSA serving key is unusable".to_owned()))?;
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => Ok(rsa::pss::SigningKey::<Sha256>::new(key)
            .sign(message)
            .to_bytes()
            .to_vec()),
        SignatureScheme::RSA_PSS_SHA384 => Ok(rsa::pss::SigningKey::<Sha384>::new(key)
            .sign(message)
            .to_bytes()
            .to_vec()),
        SignatureScheme::RSA_PSS_SHA512 => Ok(rsa::pss::SigningKey::<Sha512>::new(key)
            .sign(message)
            .to_bytes()
            .to_vec()),
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
            .sign(message)
            .to_bytes()
            .to_vec()),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(rsa::pkcs1v15::SigningKey::<Sha384>::new(key)
            .sign(message)
            .to_bytes()
            .to_vec()),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(rsa::pkcs1v15::SigningKey::<Sha512>::new(key)
            .sign(message)
            .to_bytes()
            .to_vec()),
        // `choose_scheme` only hands out schemes from the supported set,
        // so a scheme outside it means a resolver/key mismatch — refuse
        // the signature rather than guess a padding.
        _ => Err(rustls::Error::General(
            "tls: the negotiated scheme does not fit an RSA serving key".to_owned(),
        )),
    }
}

/// The serving-certificate resolver: the live [`CertifiedKey`] behind an
/// [`ArcSwapOption`], so [`SwapResolver::swap`] publishes a new
/// certificate + key pair for the very NEXT handshake — the resume
/// contract's TLS half (no re-listen, no restart; the swap IS the
/// reload).
///
/// One resolver serves one certificate; SNI is not a Wardstone concern
/// (the instance serves exactly one UI leaf), so the `ClientHello` is
/// deliberately ignored — every handshake gets the current pair or, if
/// nothing was ever swapped in, nothing (the handshake fails closed, the
/// way a listener with no certificate must).
pub struct SwapResolver {
    slot: ArcSwapOption<CertifiedKey>,
}

impl SwapResolver {
    /// An empty resolver: serves nothing until the first [`swap`].
    ///
    /// [`swap`]: SwapResolver::swap
    pub fn new() -> Self {
        SwapResolver {
            slot: ArcSwapOption::new(None),
        }
    }

    /// Publish `chain` + `key` as the served pair, taking effect for the
    /// very next handshake. The key's DER reservation moves into arena
    /// custody inside the [`ArenaKey`]; the previous pair's mirror dies
    /// with the handshakes that held it, and its canonical reservation is
    /// wiped the moment the swap drops the old `CertifiedKey` (any
    /// in-flight handshake keeps its own mirror alive through its signer).
    pub fn swap(&self, chain: Vec<CertificateDer<'static>>, key: ArenaKey) {
        let certified = CertifiedKey::new(chain, Arc::new(key));
        self.slot.swap(Some(Arc::new(certified)));
    }

    /// [`SwapResolver::swap`] over a certificate PEM: parses every
    /// `CERTIFICATE` block (leaf first — the order the file carries),
    /// then swaps. The certificates are PUBLIC material (they travel to
    /// every connecting browser); only the key crosses in arena custody.
    pub fn swap_pem(&self, cert_pem: &str, key: ArenaKey) -> Result<(), CaError> {
        let chain = chain_from_pem(cert_pem)?;
        self.swap(chain, key);
        Ok(())
    }
}

impl Default for SwapResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SwapResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the pair itself: `CertifiedKey`'s Debug would print the
        // key's Debug (ours is custody-safe, but the resolver's state is
        // the operator's concern, not the material's).
        let live = self.slot.load_full().is_some();
        f.debug_struct("SwapResolver").field("live", &live).finish()
    }
}

impl rustls::server::ResolvesServerCert for SwapResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.slot.load_full()
    }
}

/// Every `-----BEGIN CERTIFICATE-----` block in `pem`, decoded to its
/// DER. The same hand-parse the crate's old `pem_to_der` performed (the
/// workspace's own base64 encoder; no extra PEM crate on top of rustls's
/// pki-types, which take DER only), extended to chains: a multi-block
/// PEM serves its blocks in file order, and a PEM with no certificate
/// block is a typed refusal.
pub(crate) fn chain_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, CaError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut chain = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line == BEGIN {
            if inside {
                return Err(CaError::X509(
                    "tls: a PEM BEGIN appeared inside a certificate block".to_owned(),
                ));
            }
            inside = true;
            body.clear();
        } else if line == END {
            if !inside {
                return Err(CaError::X509(
                    "tls: a PEM END appeared without a BEGIN".to_owned(),
                ));
            }
            inside = false;
            let der = BASE64
                .decode(body.as_str())
                .map_err(|_| CaError::X509("tls: a PEM body is not valid base64".to_owned()))?;
            chain.push(CertificateDer::from(der));
            body.clear();
        } else if inside {
            body.push_str(line);
        }
    }
    if inside {
        return Err(CaError::X509(
            "tls: a PEM BEGIN was never closed by an END".to_owned(),
        ));
    }
    if chain.is_empty() {
        return Err(CaError::X509(
            "tls: the certificate PEM carries no CERTIFICATE block".to_owned(),
        ));
    }
    Ok(chain)
}

/// Build the rustls [`rustls::ServerConfig`] around `resolver`.
///
/// The `ring` crypto provider is selected explicitly: the workspace pins
/// BOTH rustls edges with default features OFF (see the workspace
/// `Cargo.toml` — `aws-lc-rs` cannot build in this container image), and
/// no global default is installed, so this process makes the choice
/// per-config instead of relying on mutable process-wide state.
///
/// No client certificate is accepted: the browser authenticates with its
/// login, not with client certificates.
pub fn rustls_server_config(resolver: Arc<SwapResolver>) -> Result<rustls::ServerConfig, CaError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| CaError::X509(format!("tls: protocol versions: {err}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver))
}

/// # Unit tests
///
/// The REAL stack is exercised by `tests/tls_signer_test.rs` — a full
/// rustls handshake per leaf kind and the swap's effect on the next
/// handshake. These unit tests pin the pure pieces: scheme negotiation
/// (client preference, fail-closed on nothing offered) and the PEM chain
/// parse.
#[cfg(test)]
mod tests {
    use super::*;

    /// A real minted P-256 leaf key in arena custody (the same
    /// generation every serving leaf uses).
    fn p256_key() -> ArenaKey {
        let (_key_pair, der) =
            ws_ca::leafkey::generate_leaf_key(LeafKeyType::EcdsaP256).expect("the leaf key mints");
        let buf = ws_secmem::global()
            .expect("the protected pool initializes")
            .alloc_copy(&der)
            .expect("the arena holds the key");
        ArenaKey::new(buf, LeafKeyType::EcdsaP256)
    }

    /// `choose_scheme` walks the CLIENT's offered list: the first offered
    /// scheme the key can produce wins, even when the server's own
    /// preference would have picked a different one.
    #[test]
    fn choose_scheme_follows_the_client_preference() {
        let key = p256_key();
        let signer = key
            .choose_scheme(&[
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ])
            .expect("the P-256 key accepts the offered ECDSA scheme");
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);

        // An offer the key cannot satisfy answers None (fail closed —
        // rustls turns it into a handshake refusal, never a fallback
        // scheme).
        assert!(
            key.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .is_none(),
            "an RSA-only offer cannot be served by an ECDSA key"
        );
        assert!(
            key.choose_scheme(&[]).is_none(),
            "an empty offer serves nothing"
        );
    }

    /// The negotiation covers every leaf kind's scheme set: the RSA kinds
    /// answer both PSS and PKCS#1 arms per the client's choice, Ed25519
    /// its single scheme. (`choose_scheme` mirrors the DER but never
    /// parses it, so the RSA arms can carry a stand-in reservation — the
    /// real RSA keys are exercised end-to-end by the handshake suite.)
    #[test]
    fn choose_scheme_covers_the_rsa_and_ed25519_sets() {
        let stand_in = ws_secmem::global()
            .expect("the protected pool initializes")
            .alloc_copy(b"not-a-key-choose_scheme-never-parses")
            .expect("the arena holds the stand-in");
        let rsa = ArenaKey::new(stand_in, LeafKeyType::Rsa2048);
        assert_eq!(
            rsa.choose_scheme(&[SignatureScheme::RSA_PSS_SHA512])
                .expect("the PSS arm serves")
                .scheme(),
            SignatureScheme::RSA_PSS_SHA512
        );
        assert_eq!(
            rsa.choose_scheme(&[
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA256
            ])
            .expect("the PKCS#1 arm serves")
            .scheme(),
            SignatureScheme::RSA_PKCS1_SHA384,
            "the client's first offered scheme wins over the server order"
        );

        let (_key_pair, der) =
            ws_ca::leafkey::generate_leaf_key(LeafKeyType::Ed25519).expect("the leaf key mints");
        let buf = ws_secmem::global()
            .expect("the protected pool initializes")
            .alloc_copy(&der)
            .expect("the arena holds the key");
        let ed = ArenaKey::new(buf, LeafKeyType::Ed25519);
        assert_eq!(
            ed.choose_scheme(&[
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519
            ])
            .expect("the Ed25519 arm serves")
            .scheme(),
            SignatureScheme::ED25519
        );
        assert_eq!(ed.algorithm(), SignatureAlgorithm::ED25519);
        assert_eq!(rsa.algorithm(), SignatureAlgorithm::RSA);
    }

    /// `chain_from_pem` decodes every CERTIFICATE block in file order and
    /// refuses the damaged shapes (a stray END, an unclosed BEGIN, a
    /// non-base64 body, an empty PEM).
    #[test]
    fn chain_from_pem_decodes_blocks_and_refuses_damage() {
        use base64::engine::general_purpose::STANDARD as BASE64;

        let first = b"first certificate der";
        let second = b"second certificate der";
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            BASE64.encode(first),
            BASE64.encode(second),
        );
        let chain = chain_from_pem(&pem).expect("the two blocks parse");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].as_ref(), first);
        assert_eq!(chain[1].as_ref(), second);

        assert!(
            chain_from_pem("-----BEGIN CERTIFICATE-----\nnot base64!!!\n-----END CERTIFICATE-----")
                .is_err(),
            "a non-base64 body is refused"
        );
        assert!(
            chain_from_pem("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----").is_err(),
            "an END before a BEGIN is refused"
        );
        assert!(
            chain_from_pem("-----BEGIN CERTIFICATE-----\nAAAA").is_err(),
            "an unclosed BEGIN is refused"
        );
        assert!(
            chain_from_pem("no blocks at all").is_err(),
            "a PEM without a CERTIFICATE block is refused"
        );
    }
}
