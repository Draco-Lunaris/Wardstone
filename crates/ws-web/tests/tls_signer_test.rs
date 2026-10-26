//! Task 8's arena-backed TLS signer: the serving key never leaves the
//! protected arena — [`ws_web::tls_signer::ArenaKey`] holds its PKCS#8 DER
//! in a ws-secmem reservation, and every signature reconstructs the
//! RustCrypto key on the stack from that DER and drops it again.
//!
//! The suite exercises the REAL TLS stack: for every pinnable
//! [`LeafKeyType`] it mints a self-signed certificate (ws-ca's own
//! `generate_leaf_key` — the same generation every serving leaf uses),
//! serves it through [`ws_web::tls_signer::SwapResolver`] +
//! [`ws_web::tls_signer::rustls_server_config`] on an ephemeral loopback
//! listener, and completes a rustls handshake against it with a
//! ring-provider client that trusts the minted certificate. The echo
//! round-trip proves the handshake produced a usable data channel —
//! i.e. the signature the ArenaKey produced verified client-side.
//!
//! DB-free by design: this suite takes no advisory-lock key (keys in
//! the `0x0057_4144_5354_00xx` family belong to the database suites; the
//! next free key, 0x0021, stays free). The real global arena backs every
//! test (Ruling 20: no dedicated test pool).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ws_ca::leafkey::{generate_leaf_key, LeafKeyType, ALL_LEAF_KEY_TYPES};
use ws_web::tls_signer::{rustls_server_config, ArenaKey, SwapResolver};

/// The SAN every minted test certificate carries (and the name the client
/// connects as): a plain DNS name the rustls client name-checks against.
const TEST_NAME: &str = "localhost";

/// Mint a self-signed leaf of `kind`: the certificate DER and the key's
/// PKCS#8 DER as a protected-arena reservation (the same RAM custody the
/// serving leaves hold — Ruling 20's real global pool).
fn mint_leaf(
    kind: LeafKeyType,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    ws_secmem::SecretBuf,
) {
    let (key_pair, private_key_der) =
        generate_leaf_key(kind).expect("the leaf key generation succeeds");
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, TEST_NAME);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![rcgen::SanType::DnsName(
        TEST_NAME
            .try_into()
            .expect("the test SAN is a valid DNS name"),
    )];
    let certificate = params
        .self_signed(&key_pair)
        .expect("the self-signed certificate mints");
    let der = ws_secmem::global()
        .expect("the protected pool initializes")
        .alloc_copy(&private_key_der)
        .expect("the arena holds the serving key");
    (certificate.der().clone(), der)
}

/// A ring-provider rustls client that trusts exactly `certs` and no
/// other root (the handshakes must verify against the minted
/// certificate, not any system store).
fn client_connector(
    certs: &[rustls::pki_types::CertificateDer<'static>],
) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert.clone())
            .expect("the minted certificate parses");
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the client protocol versions build")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Serve echo over TLS on an ephemeral loopback listener until the test
/// process ends. Every accepted connection gets one TLS handshake and one
/// echo round-trip; the swap test reconnects through the SAME listener.
async fn spawn_tls_server(config: rustls::ServerConfig) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the loopback TLS listener");
    let addr = listener.local_addr().expect("the listener's local address");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0u8; 1024];
                let read = tls.read(&mut buffer).await.unwrap_or(0);
                let _ = tls.write_all(&buffer[..read]).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// One client exchange against `addr`: handshake, a ping/pong round-trip,
/// and the SHA-256 fingerprint of the certificate the CLIENT saw. The
/// connector is built FRESH per call: a shared `ClientConfig` carries
/// rustls's in-memory session cache, a TLS 1.3 resumption of the previous
/// session never consults the server's cert resolver, and the client would
/// replay the cached (old) chain — invisible here as a stale fingerprint,
/// invisible in production as a benign continued session. A fresh config
/// forces every exchange here to be a FULL handshake through the
/// resolver, which is the behavior under test.
async fn exchange_fingerprint(
    addr: SocketAddr,
    certs: &[rustls::pki_types::CertificateDer<'static>],
) -> String {
    let connector = client_connector(certs);
    let exchange = async {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the TCP connect");
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from(TEST_NAME).expect("the server name parses"),
                stream,
            )
            .await
            .expect("the TLS handshake completes");
        tls.write_all(b"ping").await.expect("the ping sends");
        let mut buffer = [0u8; 64];
        let read = tls.read(&mut buffer).await.expect("the pong arrives");
        assert_eq!(&buffer[..read], b"ping", "the echo round-trips");
        let peer = tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("the client saw the server certificate")
            .first()
            .expect("one leaf certificate")
            .clone();
        hex::encode(sha2::Sha256::digest(peer.as_ref()))
    };
    tokio::time::timeout(Duration::from_secs(15), exchange)
        .await
        .expect("the exchange finishes")
        .to_string()
}

/// The SHA-256 fingerprint of a certificate DER (the comparison side of
/// the client-seen fingerprints).
fn fingerprint(cert: &rustls::pki_types::CertificateDer<'static>) -> String {
    hex::encode(sha2::Sha256::digest(cert.as_ref()))
}

/// Every pinnable leaf key type completes a TLS handshake served from the
/// protected arena: the certificate is minted per kind, the key crosses
/// as an [`ArenaKey`], and the ring-provider client both VERIFIES the
/// handshake signature and echoes data over the channel — so a kind whose
/// stack-built key signs wrongly fails here, not in production.
#[tokio::test]
async fn each_leaf_key_type_completes_a_handshake() {
    for kind in ALL_LEAF_KEY_TYPES {
        let (cert, key) = mint_leaf(*kind);
        let resolver = Arc::new(SwapResolver::new());
        resolver.swap(vec![cert.clone()], ArenaKey::new(key, *kind));
        let config =
            rustls_server_config(resolver).expect("the server config builds for the arena key");
        let addr = spawn_tls_server(config).await;
        let seen = exchange_fingerprint(addr, std::slice::from_ref(&cert)).await;
        assert_eq!(
            seen,
            fingerprint(&cert),
            "{kind:?}: the client completed the handshake against the minted certificate"
        );
    }
}

/// The swap is the reload: a resolver that already served one certificate
/// presents the swapped one to the very NEXT handshake — same listener,
/// same config, no re-listen — and the client sees the new leaf's
/// fingerprint.
#[tokio::test]
async fn a_swap_takes_effect_for_the_next_handshake() {
    let (cert_a, key_a) = mint_leaf(LeafKeyType::EcdsaP256);
    let (cert_b, key_b) = mint_leaf(LeafKeyType::EcdsaP256);
    assert_ne!(
        fingerprint(&cert_a),
        fingerprint(&cert_b),
        "the two minted leaves are distinct"
    );

    let resolver = Arc::new(SwapResolver::new());
    resolver.swap(
        vec![cert_a.clone()],
        ArenaKey::new(key_a, LeafKeyType::EcdsaP256),
    );
    let addr =
        spawn_tls_server(rustls_server_config(resolver.clone()).expect("the server config builds"))
            .await;
    // Each exchange trusts BOTH minted leaves and builds its own client
    // config: each handshake must verify on its own merits, so the
    // fingerprint — not the root set — tells which certificate was
    // served.
    let seen_a = exchange_fingerprint(addr, &[cert_a.clone(), cert_b.clone()]).await;
    assert_eq!(
        seen_a,
        fingerprint(&cert_a),
        "the first handshake served the first leaf"
    );

    resolver.swap(
        vec![cert_b.clone()],
        ArenaKey::new(key_b, LeafKeyType::EcdsaP256),
    );
    let seen_b = exchange_fingerprint(addr, &[cert_a.clone(), cert_b.clone()]).await;
    assert_eq!(
        seen_b,
        fingerprint(&cert_b),
        "the swap took effect for the very next handshake"
    );
}
