//! The loopback OIDC provider fixture (Task 19 — deferred here from
//! Task 12 by controller ruling): a stub server that plays a complete
//! OIDC provider for the e2e suite, so ws-api's callback route performs a
//! REAL end-to-end exchange — the code ws-api received is traded at this
//! token endpoint for an id_token whose RS256 signature ws-api verifies
//! against THIS provider's JWKS, exactly as it would against a deployed
//! Keycloak.
//!
//! # Stub shape
//!
//! A blocking `std::net::TcpListener` on loopback serving on a dedicated
//! OS thread — the house fixture pattern (ws-auth's and ws-api's oidc
//! test stubs: tokio listeners fail inside test contexts, and a blocking
//! stub is runtime-independent). It answers until the test process exits;
//! loopback-only material, no explicit teardown. The request is read
//! properly (headers, then the `Content-Length` body) before the stub
//! dispatches and answers with `Connection: close`.
//!
//! # Endpoints
//!
//! - `GET /.well-known/openid-configuration` — the discovery document;
//!   the issuer, authorization, token, and JWKS URLs all point at THIS
//!   server (ws-auth's `discover` requires all four fields and passes the
//!   absolute values it finds straight to the next hop).
//! - `POST /token` — an RFC 6749 section 5.1 success body: `access_token`
//!   (`Bearer`-type fixture material ws-api must never relay to a
//!   browser), `token_type`, `expires_in`, and an `id_token` signed RS256
//!   with the key whose public half the JWKS publishes. The claims pin
//!   exactly what ws-auth's `identity_from_response` verifies: `iss` =
//!   the discovery issuer, `aud` = the configured client_id, `iat`/`exp`
//!   inside its 60-second leeway, and the identity claims it turns into
//!   its `OidcIdentity` downstream (`sub`, `email` with
//!   `email_verified`, `name`/`preferred_username`).
//! - `GET /jwks` — `{keys: [{kty RSA, alg RS256, use sig, kid, n, e}]}`.
//!
//! # Key handling
//!
//! The RSA keypair is generated AT TEST TIME with the `openssl` CLI — the
//! house fixture pattern (ws-ca's interop tests drive the binary; OpenSSL
//! 3.0.13 is on the build host) — never a baked-in commit artifact:
//! `openssl genrsa -out <pem> 2048` produces a PKCS#1
//! `BEGIN RSA PRIVATE KEY` PEM, which jsonwebtoken's `EncodingKey::
//! from_rsa_pem` (the workspace pin, ws-auth's own signer) loads; `openssl
//! rsa -noout -modulus` yields the big-endian modulus hex, which becomes
//! the JWK `n` (base64url-unpadded, leading zero bytes stripped); the
//! exponent is genrsa's default 65537 → the JWK `e` `AQAB`. The key file
//! lives in a process-unique temp directory and is removed once the PEM
//! string is in memory.
//!
//! # What the fixture deliberately does NOT do
//!
//! It mints no Wardstone-shaped material: every token it issues is
//! provider-side (`ws-web-e2e-fixture-access-token` is an OAuth access
//! token only ws-api's exchange and ws-web's store ever hold — which is
//! precisely what the e2e suite's token-boundary assertions prove).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use uuid::Uuid;

/// This fixture's signing key id: the JWKS `kid` the id_token header
/// carries and ws-api's verification looks up before decoding.
const KID: &str = "ws-web-e2e-oidc-key";

/// The fixed authorization code the flow carries: ws-api posts whatever
/// code the browser bounced in; the grant's VALUE is opaque to the
/// exchange (the signed id_token is the assertion that matters), so the
/// fixture honors exactly this one code.
pub const CODE: &str = "ws-web-e2e-authorization-code";

/// The provider-side OAuth access token the token endpoint answers with
/// (RFC 6749 shape; never leaves the server side of the flow). Public so
/// a suite's token-boundary sweep can name it as an extra marker: if it
/// ever leaked into a browser-facing body the boundary is broken even
/// though it wears no `ws_`/`Bearer` prefix.
pub const FIXTURE_ACCESS_TOKEN: &str = "ws-web-e2e-fixture-access-token";

/// The stub provider: nothing to inspect — an in-flight test drives the
/// whole flow, and the handle only names the loopback URLs to configure
/// and navigate against.
pub struct OidcProvider {
    /// This server's issuer/base URL (`http://127.0.0.1:{port}`).
    base: String,
}

impl OidcProvider {
    /// Spawn the stub on an ephemeral loopback port with a fresh
    /// openssl-generated RSA keypair, signing id_tokens for `client_id`
    /// asserting the identity `subject` / `email` / display name `name`.
    pub fn spawn(client_id: &str, subject: &str, email: &str, name: &str) -> Self {
        let (key_pem, modulus_b64url) = generate_rsa_keypair();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind the loopback OIDC provider stub");
        let port = listener
            .local_addr()
            .expect("the stub's local address")
            .port();
        // The issuer is the base URL and every endpoint is this server —
        // the discovery document ws-auth's `discover` resolves.
        let issuer = format!("http://127.0.0.1:{port}");
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })
        .to_string();
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": modulus_b64url,
                "e": AQAB_B64URL,
            }]
        })
        .to_string();
        // One id_token signed once at spawn (its `exp` is five minutes
        // out — far inside every replay the e2e suite makes against it).
        let id_token = sign_id_token(&key_pem, &issuer, client_id, subject, email, name);
        let token_body = json!({
            "access_token": FIXTURE_ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })
        .to_string();
        std::thread::spawn(move || {
            serve(listener, discovery, jwks, token_body);
        });
        Self { base: issuer }
    }

    /// The discovery URL to seed `PUT /api/v1/oidc/config` with.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base)
    }

    /// The authorization endpoint the start route's redirect must open.
    pub fn authorization_endpoint(&self) -> String {
        format!("{}/authorize", self.base)
    }
}

/// The base64url of the RSA public exponent 65537 (`0x010001`), genrsa's
/// default — the JWK `e`.
const AQAB_B64URL: &str = "AQAB";

/// The request-loop: read each connection's request properly (the header
/// block, then any `Content-Length` body — the token endpoint receives a
/// form-encoded POST the stub must drain before answering), dispatch on
/// the request path, and answer with `Connection: close`.
fn serve(listener: std::net::TcpListener, discovery: String, jwks: String, token_body: String) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { break };
        let path = match read_request(&mut stream) {
            Some(path) => path,
            None => continue,
        };
        let (status, body) = if path.starts_with("/.well-known/openid-configuration") {
            ("200 OK", discovery.clone())
        } else if path.starts_with("/token") {
            ("200 OK", token_body.clone())
        } else if path.starts_with("/jwks") {
            ("200 OK", jwks.clone())
        } else {
            ("404 Not Found", "{\"error\":\"not_found\"}".to_string())
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Read one request: the header block, then the `Content-Length` body if
/// announced. Returns the request path (`GET /jwks HTTP/1.1` → `/jwks`).
fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
        raw.extend_from_slice(&chunk[..read]);
        let head_end = raw.windows(4).position(|window| window == b"\r\n\r\n");
        match head_end {
            Some(head_end) => {
                let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
                let announced = head
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")?
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
                    .unwrap_or(0);
                let body_read = raw.len() - head_end - 4;
                if body_read >= announced || read == 0 {
                    break;
                }
            }
            None if read == 0 => return None,
            None => continue,
        }
    }
    let first_line = String::from_utf8_lossy(&raw);
    let path = first_line
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .unwrap_or("/");
    Some(path.to_string())
}

/// Generate the fixture's RSA keypair at test time with the `openssl`
/// CLI (the house fixture pattern): the private PKCS#1 PEM and the public
/// modulus as the base64url-unpadded JWK `n`.
fn generate_rsa_keypair() -> (String, String) {
    let dir = std::env::temp_dir().join(format!(
        "ws-web-oidc-provider-key-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).expect("create the fixture key temp dir");
    let key_path: PathBuf = dir.join("key.pem");

    let run = |description: &str, args: &[&std::ffi::OsStr]| -> String {
        let out = Command::new("openssl")
            .args(args)
            .output()
            .expect("spawn openssl for the fixture keypair");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "openssl {description} failed: {text}");
        text
    };

    let _ = run(
        "genrsa",
        &[
            std::ffi::OsStr::new("genrsa"),
            std::ffi::OsStr::new("-out"),
            key_path.as_os_str(),
            std::ffi::OsStr::new("2048"),
        ],
    );
    let modulus_out = run(
        "rsa -modulus",
        &[
            std::ffi::OsStr::new("rsa"),
            std::ffi::OsStr::new("-in"),
            key_path.as_os_str(),
            std::ffi::OsStr::new("-noout"),
            std::ffi::OsStr::new("-modulus"),
        ],
    );
    let key_pem = std::fs::read_to_string(&key_path).expect("read the fixture private key");
    let _ = std::fs::remove_dir_all(&dir);

    // `Modulus=<even-length hex>`: the JWK `n` is the same integer's
    // unsigned big-endian bytes without leading zero octets.
    let mut hex = modulus_out
        .lines()
        .find_map(|line| line.strip_prefix("Modulus="))
        .expect("openssl rsa -modulus prints Modulus=<hex>")
        .trim()
        .to_string();
    while hex.starts_with("00") {
        hex.replace_range(..2, "");
    }
    assert!(hex.len() % 2 == 0, "the modulus hex is byte-aligned");
    let modulus = hex::decode(&hex).expect("the modulus hex decodes");
    (key_pem, URL_SAFE_NO_PAD.encode(modulus))
}

/// Sign `claims` as an RS256 JWT with the fixture key — the ws-auth
/// oidc-test idiom (the workspace's jsonwebtoken pin, `rust_crypto`
/// feature): RS256 header with the JWKS `kid`, claims carrying exactly
/// what `identity_from_response` verifies (`iss`/`aud`/leeway) and turns
/// into the identity (`sub`/`email`/`email_verified`/`name`).
fn sign_id_token(
    key_pem: &str,
    issuer: &str,
    audience: &str,
    subject: &str,
    email: &str,
    name: &str,
) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let now = chrono::Utc::now().timestamp();
    let claims: Value = json!({
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 300,
        "sub": subject,
        "email": email,
        "email_verified": true,
        "name": name,
        "preferred_username": name,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(key_pem.as_bytes()).expect("load the fixture RSA private key"),
    )
    .expect("sign the fixture id_token")
}
