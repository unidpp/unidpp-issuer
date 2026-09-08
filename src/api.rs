//! HTTP surface: axum router, handlers, `Config`, `TestServer`.
//!
//! Conventions (mirroring `unidpp-registry`): every response is as-of
//! stamped (`x-as-of` header plus an `as_of` body field); not-found
//! responses are no-information — identical bytes for unknown passports
//! and anything deliberately unresolvable (I12 enumeration resistance);
//! mutations require a Bearer token when `UNIDPP_ISSUER_ADMIN_TOKEN` is
//! set (open in dev mode); every mutation is appended to the audit log
//! (`GET /admin/log`) and, when `UNIDPP_ISSUER_STATE_FILE` is set,
//! journaled as JSONL and replayed on start.
//!
//! The passport lifecycle surface:
//!
//! | endpoint | purpose |
//! |---|---|
//! | `POST /passports` | create: identity, type ref, config vector, capability class → passport id + empty log |
//! | `POST /passports/{id}/events` | append a typed event; server-signed (Ed25519) → `TrustMarker::Attested`; illegal status transitions rejected (I6) |
//! | `POST /passports/{id}/pack` | mint the Tier-A pack: real ECDSA-P256 carrier signature, QR budget enforcement |
//! | `GET /passports/{id}` | core + manifest (config vector) + log head |
//! | `GET /passports/{id}/verdict` | full-pipeline verdict + coverage (log verdict, Tier-A pack verdict, event-signature audit) |
//! | `GET /keyring` | the public anchors a verifier pins |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use unidpp_cli::commands::verify::{verify_pack_with_anchors, DEFAULT_MAX_AGE_SECS};
use unidpp_cli::encoding::{hex_decode, hex_encode, Encoding};
use unidpp_cli::packfile::{parse_budget, sign_pack_suites, DEFAULT_BUDGET};
use unidpp_cli::passport::{EventSignature, MintOptions, Passport};
use unidpp_event::{EventType, SealedEvent, TypedEvent};
use unidpp_model::{
    CapabilityClass, Granularity, PassportId, ProductIdentifier, Timestamp, TrustMarker,
};
use unidpp_signatif::keyring::{KeyId, KeyPair};
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};
use unidpp_tier_a::{TierAPacker, TierAPayload};
use unidpp_verdict::{Reading, VerdictBuilder};

use crate::events::{default_payload, payload_from_data};
use crate::keyring::{Keyring, Role};
use crate::registry::{RegistryClient, RegistryOutcome};
use crate::store::{BindingRecord, PassportRecord, ProfileRecord, Store, StoreError};

/// Deployment configuration (environment-driven; see `main.rs`).
/// Deliberately not `Clone`: the keyring holds secret-side key material.
#[derive(Debug)]
pub struct Config {
    /// Listen address.
    pub bind: SocketAddr,
    /// Bearer token guarding mutations; `None` = open (dev mode).
    pub admin_token: Option<String>,
    /// Optional JSONL journal file (append-only audit log, replayed on
    /// start).
    pub state_file: Option<PathBuf>,
    /// Optional `unidpp-registry` base URL for admin forwarding.
    pub registry_url: Option<String>,
    /// Bearer token forwarded to the registry (its admin token).
    pub registry_token: Option<String>,
    /// The server keyring (resolved at construction).
    pub keyring: Keyring,
    /// Default freshness window of the Tier-A verdict leg (seconds;
    /// `?max_age=` overrides; `0` selects static/archival semantics).
    pub default_max_age: i64,
}

impl Config {
    /// A dev-mode default config (seeded keyring, loopback, no journal).
    pub fn dev(bind: SocketAddr, seed: Option<&str>) -> Config {
        Config {
            bind,
            admin_token: None,
            state_file: None,
            registry_url: None,
            registry_token: None,
            keyring: Keyring::dev(seed).expect("dev keyring derives"),
            default_max_age: DEFAULT_MAX_AGE_SECS,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config::dev("127.0.0.1:8091".parse().expect("static bind"), None)
    }
}

impl Config {
    /// Resolve configuration from `UNIDPP_ISSUER_*` environment
    /// variables. Returns a warning when the keyring fell back to
    /// seeded-dev mode.
    pub fn from_env() -> (Config, Option<String>) {
        let mut config = Config::default();
        let mut warning = None;
        if let Ok(bind) = std::env::var("UNIDPP_ISSUER_BIND") {
            match bind.parse() {
                Ok(addr) => config.bind = addr,
                Err(_) => eprintln!("unidpp-issuer: ignoring bad UNIDPP_ISSUER_BIND `{bind}`"),
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_ISSUER_ADMIN_TOKEN") {
            if !token.is_empty() {
                config.admin_token = Some(token);
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_ISSUER_STATE_FILE") {
            if !path.is_empty() {
                config.state_file = Some(PathBuf::from(path));
            }
        }
        if let Ok(url) = std::env::var("UNIDPP_ISSUER_REGISTRY_URL") {
            if !url.is_empty() {
                config.registry_url = Some(url);
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_ISSUER_REGISTRY_TOKEN") {
            if !token.is_empty() {
                config.registry_token = Some(token);
            }
        }
        if let Ok(max_age) = std::env::var("UNIDPP_ISSUER_MAX_AGE") {
            match max_age.trim().parse::<i64>() {
                Ok(secs) => config.default_max_age = secs,
                Err(_) => {
                    eprintln!("unidpp-issuer: ignoring bad UNIDPP_ISSUER_MAX_AGE `{max_age}`")
                }
            }
        }
        let event_seed = std::env::var("UNIDPP_ISSUER_EVENT_SEED")
            .ok()
            .filter(|s| !s.is_empty());
        let pack_seed = std::env::var("UNIDPP_ISSUER_PACK_SEED")
            .ok()
            .filter(|s| !s.is_empty());
        let pack_suites = match std::env::var("UNIDPP_ISSUER_PACK_SUITE") {
            Ok(token) if !token.trim().is_empty() => {
                match crate::keyring::PackSuites::parse(&token) {
                    Ok(suites) => suites,
                    Err(e) => {
                        eprintln!("unidpp-issuer: bad UNIDPP_ISSUER_PACK_SUITE: {e}");
                        std::process::exit(1);
                    }
                }
            }
            _ => crate::keyring::PackSuites::default(),
        };
        match (event_seed, pack_seed) {
            (Some(event), Some(pack)) => {
                match Keyring::from_env_seeds_with(&event, &pack, &pack_suites) {
                    Ok(keyring) => config.keyring = keyring,
                    Err(e) => {
                        eprintln!("unidpp-issuer: {e}; refusing to fall back to seeded-dev mode");
                        std::process::exit(1);
                    }
                }
            }
            (None, None) => {
                let seed = std::env::var("UNIDPP_ISSUER_SEED")
                    .ok()
                    .filter(|s| !s.is_empty());
                config.keyring = Keyring::with_pack_suites(seed.as_deref(), &pack_suites)
                    .expect("dev keyring derives");
                warning = Some(
                    "keyring runs in seeded-dev mode; production deployments must set \
                     UNIDPP_ISSUER_EVENT_SEED and UNIDPP_ISSUER_PACK_SEED"
                        .to_string(),
                );
            }
            _ => {
                eprintln!(
                    "unidpp-issuer: env-key mode needs both UNIDPP_ISSUER_EVENT_SEED and \
                     UNIDPP_ISSUER_PACK_SEED; refusing to fall back to seeded-dev mode"
                );
                std::process::exit(1);
            }
        }
        (config, warning)
    }
}

/// Shared application state.
pub struct AppState {
    /// Deployment configuration.
    pub config: Config,
    /// The passport/profile/binding store behind the audit journal.
    pub store: Mutex<Store>,
    /// Registry forwarder (fixtures when unconfigured/unreachable).
    pub registry: RegistryClient,
}

impl AppState {
    /// Assemble state from a config (replaying the journal when set).
    pub fn new(config: Config) -> std::io::Result<AppState> {
        let store = Store::open(config.state_file.as_deref())?;
        let registry =
            RegistryClient::new(config.registry_url.clone(), config.registry_token.clone());
        Ok(AppState {
            config,
            store: Mutex::new(store),
            registry,
        })
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// The no-information 404: identical bytes for unknown passports and
/// anything deliberately unresolvable alike (I12). Never vary this
/// response.
pub const NOT_FOUND_BODY: &str = "{\"error\":\"not found\"}";

fn build_response(status: StatusCode, headers: Vec<(String, String)>, body: String) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

/// Every JSON response is as-of stamped (header + body field).
fn stamped(status: StatusCode, body: &Value, as_of: Timestamp) -> Response {
    let mut body = body.clone();
    if let Some(m) = body.as_object_mut() {
        m.insert("as_of".into(), json!(as_of.to_string()));
    }
    build_response(
        status,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        serde_json::to_string_pretty(&body).unwrap(),
    )
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    stamped(status, &json!({ "error": msg }), Timestamp::now())
}

fn bad_request(msg: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

fn conflict(msg: &str) -> Response {
    error_response(StatusCode::CONFLICT, msg)
}

fn over_budget(msg: &str) -> Response {
    error_response(StatusCode::PAYLOAD_TOO_LARGE, msg)
}

/// The no-information 404.
fn not_found() -> Response {
    build_response(
        StatusCode::NOT_FOUND,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), Timestamp::now().to_string()),
        ],
        NOT_FOUND_BODY.to_string(),
    )
}

fn unauthorized() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn store_error(e: StoreError) -> Response {
    match e {
        StoreError::NotFound => not_found(),
        StoreError::Conflict(m) => conflict(&m),
        StoreError::Invalid(m) => bad_request(&m),
    }
}

// ---------------------------------------------------------------------------
// Body/query parsing
// ---------------------------------------------------------------------------

fn parse_body(body: &str) -> Result<Value, Response> {
    serde_json::from_str(body).map_err(|e| bad_request(&format!("invalid JSON body: {e}")))
}

fn req_str(v: &Value, key: &str) -> Result<String, Response> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| bad_request(&format!("`{key}` is required")))
}

fn opt_str(v: &Value, key: &str) -> Result<Option<String>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
        Some(_) => Err(bad_request(&format!("`{key}` must be a non-empty string"))),
    }
}

fn opt_ts(v: &Value, key: &str) -> Result<Option<Timestamp>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| bad_request(&format!("`{key}`: {e}"))),
        Some(_) => Err(bad_request(&format!("`{key}` must be an RFC 3339 string"))),
    }
}

fn opt_bool(v: &Value, key: &str) -> Result<Option<bool>, Response> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(bad_request(&format!("`{key}` must be a boolean"))),
    }
}

/// The config vector: an array of non-empty strings (a single string is
/// accepted and lifted into a one-element vector).
fn opt_config(v: &Value) -> Result<Vec<String>, Response> {
    match v.get("config").or_else(|| v.get("configuration")) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(vec![s.trim().to_string()]),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str().map(str::trim) {
                    Some(s) if !s.is_empty() => out.push(s.to_string()),
                    _ => {
                        return Err(bad_request(
                            "`config` must be an array of non-empty strings",
                        ))
                    }
                }
            }
            Ok(out)
        }
        Some(_) => Err(bad_request(
            "`config` must be an array of non-empty strings",
        )),
    }
}

/// Parse a capability class: `S0`-`S3` codes or canonical names (the
/// core's `parse_token` accepts the names; the codes are the operator
/// shorthand the CLI also accepts).
fn parse_capability(s: &str) -> Result<CapabilityClass, Response> {
    for class in CapabilityClass::ALL {
        if s.eq_ignore_ascii_case(class.code()) || s.eq_ignore_ascii_case(class.as_str()) {
            return Ok(*class);
        }
    }
    Err(bad_request(&format!(
        "`capability` `{s}` is unknown (expected S0-S3 or {})",
        CapabilityClass::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join("/")
    )))
}

/// The point-in-time query instant.
fn parse_at(params: &HashMap<String, String>) -> Result<Option<Timestamp>, Response> {
    let raw = params
        .get("at")
        .or_else(|| params.get("asof"))
        .map(String::as_str);
    match raw {
        None | Some("") => Ok(None),
        Some(s) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| bad_request(&format!("invalid `at` parameter: {e}"))),
    }
}

fn opt_query(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params
        .get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn require_admin(app: &AppState, headers: &HeaderMap) -> Option<Response> {
    let token = app.config.admin_token.as_ref()?;
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got == Some(token.as_str()) {
        None
    } else {
        Some(unauthorized())
    }
}

// ---------------------------------------------------------------------------
// Passport views
// ---------------------------------------------------------------------------

/// The full passport view: the CLI-compatible document (schema, log,
/// signatures — loadable by `unidpp pack`/`verify` verbatim) plus the
/// issuer's manifest layer (config vector) and the replayed state.
fn passport_view(record: &PassportRecord, at: Option<Timestamp>) -> Value {
    let document = &record.document;
    let log = &document.log;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let events: Vec<&SealedEvent> = match at {
        Some(t) => log.as_of(t).collect(),
        None => log.sealed().iter().collect(),
    };
    let (status, safety, custodian) = crate::store::replay_state(events);
    let head = match at {
        Some(t) => log.state_hash_at(t),
        None => log.head(),
    };
    let mut v = serde_json::to_value(document).expect("passport documents are serde data");
    let m = v.as_object_mut().expect("document serializes to an object");
    m.insert("config".into(), json!(record.config));
    m.insert("status".into(), json!(status));
    m.insert("safety".into(), json!(safety));
    if let Some(c) = custodian {
        m.insert("custodian".into(), json!(c));
    }
    m.insert(
        "log_head".into(),
        head.map(|h| json!(h.hex())).unwrap_or(Value::Null),
    );
    m.insert("events".into(), json!(log.len()));
    m.insert("as_of".into(), json!(as_of.to_string()));
    v
}

/// Compact creation response: the passport id and its fresh state.
fn created_view(record: &PassportRecord, audit_seq: u64) -> Value {
    let document = &record.document;
    json!({
        "passport_id": document.passport_id.as_str(),
        "schema": document.schema,
        "product_id": document.product_id.to_string(),
        "granularity": document.product_id.granularity.to_string(),
        "type_ref": document.type_ref,
        "config": record.config,
        "capability": document.capability,
        "eo_id": document.eo_id,
        "resolver_uri": document.resolver_uri,
        "validity": serde_json::to_value(document.validity).expect("serde interval"),
        "created_at": document.created_at.to_string(),
        "status": "issued",
        "log": { "len": 0, "head": Value::Null },
        "audit_seq": audit_seq,
    })
}

/// Passport id for a freshly issued document: content- and time-derived
/// slug (I1: one subject, one identity — deterministic for the same
/// input and minting moment).
fn derive_passport_id(product_id: &ProductIdentifier, at: Timestamp) -> PassportId {
    let material = format!("unidpp-issuer/mint|{}|{}|{}", product_id, at.secs, at.nanos);
    let digest = unidpp_model::sha256(&[material.as_bytes()]);
    PassportId::new(&format!("urn:unidpp:passport:iss-{}", &digest.hex()[..12]))
        .expect("derived passport id is well-formed")
}

/// Sign an event's canonical body with the keyring's Ed25519 key and
/// produce the document's signature record.
fn sign_event(key: &KeyPair, seq: u64, body: &[u8]) -> Result<EventSignature, String> {
    let slot = SignatureSlot::sign(key, SigningDomain::ArtifactEvent, body)
        .map_err(|e| format!("event signing failed: {e}"))?;
    let signature = slot
        .signature
        .as_deref()
        .expect("SignatureSlot::sign fills the value");
    Ok(EventSignature {
        seq,
        suite: slot.suite.to_string(),
        key_id: slot.key_id.to_string(),
        signature: hex_encode(signature),
    })
}

/// Cryptographically re-verify every recorded event signature against
/// the keyring's event anchor (the verdict's self-audit leg).
fn audit_event_signatures(record: &PassportRecord, key: &KeyPair) -> Value {
    let mut verified = 0usize;
    let mut failures: Vec<Value> = Vec::new();
    for sig in &record.document.event_signatures {
        let sealed = record
            .document
            .log
            .sealed()
            .get(sig.seq as usize)
            .filter(|s| s.event.seq == sig.seq);
        let check = || -> Result<(), String> {
            let event = sealed.ok_or_else(|| {
                format!(
                    "signature names seq {} but no such event is sealed",
                    sig.seq
                )
            })?;
            let body = event
                .event
                .canonical_body()
                .map_err(|e| format!("canonical body: {e}"))?;
            let suite = Suite::parse_token(&sig.suite)
                .map_err(|e| format!("suite `{}`: {e}", sig.suite))?;
            let key_id = KeyId::new(&sig.key_id).map_err(|e| e.to_string())?;
            let signature =
                hex_decode(&sig.signature).map_err(|e| format!("signature hex: {e}"))?;
            let slot = SignatureSlot {
                suite,
                key_id,
                signature: Some(signature),
            };
            slot.verify(SigningDomain::ArtifactEvent, &body, key.public())
                .map_err(|e| e.to_string())
        };
        match check() {
            Ok(()) => verified += 1,
            Err(why) => failures.push(json!({ "seq": sig.seq, "why": why })),
        }
    }
    json!({
        "total": record.document.event_signatures.len(),
        "verified": verified,
        "failures": failures,
        "anchor": {
            "suite": key.public().suite().to_string(),
            "key_id": key.key_id().to_string(),
            "public": hex_encode(key.public().as_bytes()),
        },
    })
}

/// Mint and verify the Tier-A pack exactly as `/pack` mints it and an
/// officer's terminal verifies it — the verdict's carrier leg.
fn tier_a_verdict_leg(
    record: &PassportRecord,
    pack_seed: &[u8],
    pack_suites: &[unidpp_signatif::sign::Suite],
    anchors: &[unidpp_signatif::keyring::PublicKey],
    now: Timestamp,
    max_age: i64,
) -> Result<Value, Response> {
    let document = &record.document;
    let payload = TierAPayload::from_log(
        &document.log,
        document.product_id.clone(),
        &document.resolver_uri,
        &document.eo_id,
        document.validity,
        Vec::new(),
    );
    let (signed, minted) = sign_pack_suites(&payload, pack_seed, pack_suites)
        .map_err(|e| bad_request(&format!("pack signing: {e}")))?;
    let packer = TierAPacker::new(DEFAULT_BUDGET.0, DEFAULT_BUDGET.1);
    let packed = packer
        .pack(&signed)
        .map_err(|e| over_budget(&e.to_string()))?;
    let outcome = verify_pack_with_anchors(packed.as_slice(), anchors, now, max_age);
    let summary = outcome.payload.as_ref().map(|p| {
        json!({
            "status": p.status,
            "safety": p.safety,
            "as_of": p.as_of,
            "log_head": p.log_head.map(|h| h.hex()),
            "signatures": p.signatures.len(),
        })
    });
    Ok(json!({
        "grade": outcome.grade.token(),
        "exit_code": outcome.grade.exit_code(),
        "reading_answered": outcome.reading_answered,
        "findings": outcome.findings,
        "readings": outcome.readings,
        "coverage": outcome.coverage,
        "freshness": outcome.freshness.map(|f| f.label()),
        "trust_marker": outcome.trust_marker.map(|t| t.as_str()),
        "carrier": {
            "bytes": packed.used,
            "projected": packed.projected,
            "qr_version": packed.version,
        },
        "payload": summary,
        "signature": {
            "suite": pack_suites.first().copied().unwrap_or(Suite::EcdsaP256).to_string(),
            "key_id": minted
                .first()
                .map(|(_, k)| k.to_string())
                .unwrap_or_default(),
        },
        "signatures": minted
            .iter()
            .map(|(public, key_id)| {
                json!({
                    "suite": public.suite().to_string(),
                    "key_id": key_id.to_string(),
                })
            })
            .collect::<Vec<_>>(),
    }))
}

/// The keyring's pack-suite policy as the selection type — the
/// keyring owns the policy (it was constructed from
/// `UNIDPP_ISSUER_PACK_SUITE`); nothing else re-declares it.
fn keyring_suites(keyring: &Keyring) -> crate::keyring::PackSuites {
    crate::keyring::PackSuites::collect_suites(keyring.pack_keys().iter().map(|k| k.suite()))
}

/// Resolve the config vector against locally registered profiles.
fn config_resolution(store: &Store, record: &PassportRecord) -> Value {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    for entry in &record.config {
        match store.profile(entry) {
            Some(profile) => resolved.push(json!({
                "config": entry,
                "version": profile.version,
                "data_points": profile.data_points,
            })),
            None => unresolved.push(entry.clone()),
        }
    }
    json!({
        "vector": record.config,
        "resolved": resolved,
        "unresolved": unresolved,
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn discovery(State(app): State<Arc<AppState>>) -> Result<Response, Response> {
    let doc = json!({
        "service": "unidpp-issuer",
        "description": "UniDPP passport lifecycle issuer service: create passports, append server-signed typed events, mint Tier-A packs with real signatures, run full-pipeline verdicts",
        "endpoints": {
            "create_passport": "POST /passports",
        "list_passports": "GET /passports",
            "append_event": "POST /passports/{id}/events",
            "mint_pack": "POST /passports/{id}/pack",
            "passport": "GET /passports/{id}?at=",
            "verdict": "GET /passports/{id}/verdict?at=&max_age=",
            "keyring": "GET /keyring",
            "register_profile": "POST /admin/profiles",
            "list_profiles": "GET /admin/profiles",
            "bind_applicability": "POST /admin/applicability",
            "applicability": "GET /admin/applicability?product_type=&at=",
            "audit_log": "GET /admin/log?limit=&offset=",
            "health": "GET /healthz"
        },
        "keyring_mode": app.config.keyring.mode().as_str(),
        "signatures": {
            "events": "ed25519 (SIGNATIF infrastructure suite)",
            "packs": format!(
                "{} (configurable via UNIDPP_ISSUER_PACK_SUITE or per-request `suite`; multiple suites co-sign one pack body)",
                keyring_suites(&app.config.keyring).tokens().join(" + ")
            )
        },
        "as_of": {
            "query_parameter": "at (alias: asof)",
            "response_header": "x-as-of",
        },
        "auth": "mutations require a Bearer token when UNIDPP_ISSUER_ADMIN_TOKEN is set",
        "registry": app.config.registry_url,
    });
    Ok(stamped(StatusCode::OK, &doc, Timestamp::now()))
}

async fn healthz() -> Result<Response, Response> {
    Ok(build_response(
        StatusCode::OK,
        vec![
            ("content-type".into(), "text/plain".into()),
            ("x-as-of".into(), Timestamp::now().to_string()),
        ],
        "ok".into(),
    ))
}

/// GET /keyring — the public anchors a verifier pins.
async fn keyring(State(app): State<Arc<AppState>>) -> Result<Response, Response> {
    Ok(stamped(
        StatusCode::OK,
        &app.config.keyring.to_json(),
        Timestamp::now(),
    ))
}

/// POST /passports — create a passport: identity, type ref, config
/// vector, capability class → passport id + empty log.
async fn create_passport(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let identity = ["identity", "product_id", "id"]
        .iter()
        .find_map(|key| v.get(*key).cloned())
        .ok_or_else(|| bad_request("`identity` is required"))?;
    let identity = identity
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad_request("`identity` must be a non-empty string"))?;
    let granularity = match opt_str(&v, "granularity")? {
        Some(token) => Some(
            Granularity::parse_token(&token)
                .map_err(|e| bad_request(&format!("`granularity` `{token}`: {e}")))?,
        ),
        None => None,
    };
    let capability = match opt_str(&v, "capability")? {
        Some(token) => parse_capability(&token)?,
        None => CapabilityClass::Silent,
    };
    let valid_from = opt_ts(&v, "valid_from")?;
    let valid_to = opt_ts(&v, "valid_to")?;
    let now = Timestamp::now();
    let derived = derive_passport_id(
        &ProductIdentifier::parse(identity)
            .map_err(|e| bad_request(&format!("`identity`: {e}")))?,
        now,
    );
    let type_ref = match opt_str(&v, "type_ref")? {
        Some(t) => Some(t),
        None => opt_str(&v, "type")?,
    };
    let document = Passport::mint(MintOptions {
        id: identity.to_string(),
        granularity,
        type_ref,
        capability: capability.as_str().to_string(),
        eo_id: opt_str(&v, "eo_id")?,
        resolver_uri: opt_str(&v, "resolver_uri")?,
        passport_id: Some(
            opt_str(&v, "passport_id")?
                .map(|p| p.to_string())
                .unwrap_or_else(|| derived.as_str().to_string()),
        ),
        valid_from,
        valid_to,
    })
    .map_err(|e| bad_request(&format!("passport rejected: {e}")))?;
    let record = PassportRecord {
        document,
        config: opt_config(&v)?,
    };
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .create_passport(record.clone())
            .map_err(store_error)?
            .seq
    };
    Ok(stamped(
        StatusCode::CREATED,
        &created_view(&record, audit_seq),
        now,
    ))
}

/// GET /passports/{id} — core + manifest (config vector) + log head.
async fn get_passport(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let found = {
        let store = app.store.lock().expect("store poisoned");
        store.passport(&id).cloned()
    };
    match found {
        Some(record) => Ok(stamped(StatusCode::OK, &passport_view(&record, at), as_of)),
        None => Err(not_found()),
    }
}

/// GET /passports — the listing (ids + subjects + capability classes).
/// What an admin surface enumerates; the per-passport GET carries the
/// document.
async fn list_passports(State(app): State<Arc<AppState>>) -> Result<Response, Response> {
    let listing: Vec<Value> = {
        let store = app.store.lock().expect("store poisoned");
        store
            .passports()
            .iter()
            .map(|record| {
                let document = &record.document;
                json!({
                    "passport_id": document.passport_id.as_str(),
                    "product_id": document.product_id.to_string(),
                    "capability": document.capability.to_string(),
                    "eo_id": document.eo_id,
                    "events": document.log.sealed().len(),
                })
            })
            .collect()
    };
    let count = listing.len();
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "count": count,
            "passports": listing,
            "as_of_note": "current state; the per-passport GET serves point-in-time",
        }),
        Timestamp::now(),
    ))
}

/// POST /passports/{id}/events — append a typed event; the server signs
/// the event's canonical body with its Ed25519 key (the event carries
/// `TrustMarker::Attested`); illegal status transitions are rejected
/// (I6).
async fn append_event(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let type_token = req_str(&v, "type")?;
    let event_type = EventType::parse_token(&type_token)
        .map_err(|e| bad_request(&format!("`type` `{type_token}`: {e}")))?;
    let payload = match v.get("data").or_else(|| v.get("payload")) {
        None | Some(Value::Null) => default_payload(event_type).ok_or_else(|| {
            bad_request(&format!(
                "`data` is required for {event_type} (the payload has operator-supplied fields)"
            ))
        })?,
        Some(data) => {
            payload_from_data(event_type, data).map_err(|e| bad_request(&format!("`data`: {e}")))?
        }
    };
    let occurred_at = opt_ts(&v, "at")?.unwrap_or_else(Timestamp::now);
    let now = Timestamp::now();
    let sign = opt_bool(&v, "sign")?.unwrap_or(true);
    let trust = if sign {
        TrustMarker::Attested
    } else {
        TrustMarker::Unsigned
    };

    // Everything under one lock: existence, seq, event construction,
    // signing, and the audited append.
    let outcome = {
        let mut store = app.store.lock().expect("store poisoned");
        let Some(record) = store.passport(&id) else {
            return Err(not_found());
        };
        let seq = record.document.log.len() as u64;
        let actor_id = opt_str(&v, "actor")?.unwrap_or_else(|| record.document.eo_id.clone());
        let actor_role =
            opt_str(&v, "actor_role")?.unwrap_or_else(|| event_type.appender_role().to_string());
        let event = TypedEvent::new(
            seq,
            occurred_at,
            &actor_role,
            &actor_id,
            event_type,
            payload,
            trust,
        )
        .map_err(|e| match e {
            unidpp_event::EventError::IllegalTransition { from, to } => {
                conflict(&format!("illegal status transition {from} -> {to} (I6)"))
            }
            other => bad_request(&format!("event rejected: {other}")),
        })?;
        let body = event
            .canonical_body()
            .map_err(|e| bad_request(&format!("canonical body: {e}")))?;
        let signature = if sign {
            Some(
                sign_event(app.config.keyring.event_key(), seq, &body)
                    .map_err(|e| bad_request(&e))?,
            )
        } else {
            None
        };
        let passport_label = record.passport_id().as_str().to_string();
        let (rec, out) = store
            .append_event(&passport_label, event, signature.clone())
            .map_err(store_error)?;
        (rec.seq, out, signature, actor_id, actor_role)
    };
    let (audit_seq, out, signature, actor_id, actor_role) = outcome;
    Ok(stamped(
        StatusCode::CREATED,
        &json!({
            "passport_id": id,
            "seq": out.seq,
            "event_type": event_type,
            "occurred_at": occurred_at.to_string(),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "trust": out.trust,
            "signature": signature,
            "log_head": out.head.hex(),
            "status": out.status,
            "safety": out.safety,
            "audit_seq": audit_seq,
        }),
        now,
    ))
}

/// POST /passports/{id}/pack — mint the Tier-A offline pack with a real
/// ECDSA-P256 carrier signature (RFC 6979) and QR budget enforcement.
async fn mint_pack(
    State(app): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: String,
) -> Result<Response, Response> {
    let v = if body.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        parse_body(&body)?
    };
    let budget = match opt_str(&v, "budget")? {
        Some(token) => parse_budget(&token).map_err(|e| bad_request(&format!("`budget`: {e}")))?,
        None => DEFAULT_BUDGET,
    };
    let encoding = match opt_str(&v, "encoding")? {
        Some(token) => {
            Encoding::parse(&token).map_err(|e| bad_request(&format!("`encoding`: {e}")))?
        }
        None => Encoding::Hex,
    };
    let sign = opt_bool(&v, "sign")?.unwrap_or(true);
    // Suite selection: the body's `suite` (single token or
    // comma-separated co-signature list) overrides the deployment
    // policy for this pack.
    let suites = match opt_str(&v, "suite")?.or(opt_str(&v, "suites")?) {
        Some(token) => crate::keyring::PackSuites::parse(&token)
            .map_err(|e| bad_request(&format!("`suite`: {e}")))?,
        None => keyring_suites(&app.config.keyring),
    };
    let now = Timestamp::now();
    let found = {
        let store = app.store.lock().expect("store poisoned");
        store.passport(&id).cloned()
    };
    let Some(record) = found else {
        return Err(not_found());
    };
    let document = &record.document;
    let payload = TierAPayload::from_log(
        &document.log,
        document.product_id.clone(),
        &document.resolver_uri,
        &document.eo_id,
        document.validity,
        Vec::new(),
    );
    let (payload, signatures) = if sign {
        let (signed, minted) =
            sign_pack_suites(&payload, app.config.keyring.pack_seed(), suites.as_slice())
                .map_err(|e| bad_request(&format!("pack signing: {e}")))?;
        (
            signed,
            minted
                .iter()
                .map(|(public, key_id)| {
                    json!({
                        "suite": public.suite().to_string(),
                        "key_id": key_id.to_string(),
                        "anchor": unidpp_cli::encoding::hex_encode(public.as_bytes()),
                    })
                })
                .collect::<Vec<Value>>(),
        )
    } else {
        (payload, Vec::new())
    };
    let packer = TierAPacker::new(budget.0, budget.1);
    let packed = packer
        .pack(&payload)
        .map_err(|e| over_budget(&e.to_string()))?;
    let text = encoding.encode(packed.as_slice());
    Ok(stamped(
        StatusCode::CREATED,
        &json!({
            "passport_id": id,
            "encoding": encoding.as_str(),
            "pack": text,
            "bytes": packed.used,
            "projected": packed.projected,
            "qr_version": packed.version,
            "ec": budget.0,
            "margin": packed.margin(),
            "signature": signatures.first().cloned().unwrap_or(Value::Null),
            "signatures": signatures,
            "anchor": app.config.keyring.public_hex(Role::Pack),
            "anchors": app
                .config
                .keyring
                .pack_anchors()
                .into_iter()
                .map(|(suite, public)| {
                    (
                        suite.to_string(),
                        json!(unidpp_cli::encoding::hex_encode(public.as_bytes())),
                    )
                })
                .collect::<serde_json::Map<String, Value>>(),
        }),
        now,
    ))
}

/// GET /passports/{id}/verdict — the full-pipeline verdict + coverage:
/// the core verdict over the authoritative log, the Tier-A pack
/// verdict as an officer's terminal computes it, the server-side
/// re-verification of every recorded event signature, and the config
/// vector's resolution against registered profiles.
async fn passport_verdict(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let at = parse_at(&params)?;
    let now = at.unwrap_or_else(Timestamp::now);
    let max_age = match opt_query(&params, "max_age") {
        Some(token) => token
            .parse::<i64>()
            .map_err(|_| bad_request("`max_age` must be a number of seconds"))?,
        None => app.config.default_max_age,
    };
    let found = {
        let store = app.store.lock().expect("store poisoned");
        store.passport(&id).cloned()
    };
    let Some(record) = found else {
        return Err(not_found());
    };
    let log = &record.document.log;

    // Log verdict: chain, anchor at the log head, event-signature
    // evidence. Ed25519 event signatures have no core carrier slot
    // (documented deviation), so they are reported through the
    // dedicated audit leg instead of SigSlot framing.
    let mut builder = VerdictBuilder::new(log, now)
        .answering(Reading::CurrentState)
        .attested_by_third_party(!record.document.event_signatures.is_empty());
    if let Some(head) = log.head() {
        builder = builder.with_anchor(head);
    }
    let verdict = builder.build();

    let event_audit = audit_event_signatures(&record, app.config.keyring.event_key());
    let anchors: Vec<unidpp_signatif::keyring::PublicKey> = app
        .config
        .keyring
        .pack_anchors()
        .into_iter()
        .map(|(_, public)| public)
        .collect();
    let tier_a = tier_a_verdict_leg(
        &record,
        app.config.keyring.pack_seed(),
        keyring_suites(&app.config.keyring).as_slice(),
        &anchors,
        now,
        max_age,
    )?;
    let config = {
        let store = app.store.lock().expect("store poisoned");
        config_resolution(&store, &record)
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "passport_id": id,
            "verified_at": now.to_string(),
            "reading_answered": "current-state",
            "log": verdict,
            "event_signatures": event_audit,
            "tier_a": tier_a,
            "config": config,
        }),
        now,
    ))
}

// ---------------------------------------------------------------------------
// Admin handlers (profiles / applicability forwarding)
// ---------------------------------------------------------------------------

/// POST /admin/profiles — register a profile locally and forward it to
/// the configured registry (fixtures otherwise).
async fn register_profile(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let profile_id = req_str(&v, "profile_id")?;
    let definition = req_str(&v, "definition")?;
    let version = opt_str(&v, "version")?.unwrap_or_else(|| "1.0.0".to_string());
    let register_id = opt_str(&v, "register_id")?;
    let jurisdiction = opt_str(&v, "jurisdiction")?;
    let data_points = match v.get("data_points") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str().map(str::trim) {
                    Some(s) if !s.is_empty() => out.push(s.to_string()),
                    _ => {
                        return Err(bad_request(
                            "`data_points` must be an array of non-empty strings",
                        ))
                    }
                }
            }
            out
        }
        Some(_) => return Err(bad_request("`data_points` must be an array of strings")),
    };
    let now = Timestamp::now();
    let profile = ProfileRecord {
        profile_id: profile_id.clone(),
        definition: definition.clone(),
        version: version.clone(),
        register_id: register_id.clone(),
        jurisdiction: jurisdiction.clone(),
        data_points,
        registered_at: now,
    };
    // Forward first (a rejection from a live registry must surface
    // before anything is journaled), then journal locally.
    let forward_body = json!({
        "register_id": register_id.clone().unwrap_or_else(|| "unidpp-issuer".to_string()),
        "item_id": profile_id,
        "class": "profile",
        "definition": definition,
        "version": version,
        "submitting_organization": "unidpp-issuer",
    });
    let outcome: RegistryOutcome = app
        .registry
        .register_profile(&forward_body)
        .await
        .map_err(|e| bad_request(&e))?;
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .register_profile(profile.clone(), outcome.via())
            .map_err(store_error)?
            .seq
    };
    let mut body = serde_json::to_value(&profile).expect("profile records are serde data");
    if let Some(m) = body.as_object_mut() {
        m.insert("via".into(), json!(outcome.mode.as_str()));
        if let Some(detail) = &outcome.detail {
            if outcome.mode == crate::registry::RegistryMode::Registry {
                m.insert("registry_response".into(), json!(detail));
            } else {
                m.insert("detail".into(), json!(detail));
            }
        }
        m.insert("audit_seq".into(), json!(audit_seq));
    }
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// GET /admin/profiles — locally registered profiles.
async fn list_profiles(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let profiles = {
        let store = app.store.lock().expect("store poisoned");
        store
            .profiles()
            .into_iter()
            .cloned()
            .collect::<Vec<ProfileRecord>>()
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "count": profiles.len(),
            "profiles": profiles,
        }),
        Timestamp::now(),
    ))
}

/// POST /admin/applicability — bind a profile to a product type
/// (forwarded to the registry when configured).
async fn bind_applicability(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let v = parse_body(&body)?;
    let profile_id = req_str(&v, "profile_id")?;
    let product_type = req_str(&v, "product_type")?;
    let profile_version = opt_str(&v, "profile_version")?;
    let now = Timestamp::now();
    let effective_from = opt_ts(&v, "effective_from")?.unwrap_or(now);
    let effective_until = opt_ts(&v, "effective_until")?;
    if let Some(until) = effective_until {
        if until < effective_from {
            return Err(bad_request(
                "`effective_until` must not precede `effective_from`",
            ));
        }
    }
    let retroactive = opt_bool(&v, "retroactive")?.unwrap_or(false);
    let binding = BindingRecord {
        profile_id: profile_id.clone(),
        product_type: product_type.clone(),
        profile_version: profile_version.clone(),
        effective_from,
        effective_until,
        retroactive,
        registered_at: now,
    };
    // The local store validates that the profile is known here.
    {
        let store = app.store.lock().expect("store poisoned");
        if store.profile(&profile_id).is_none() {
            return Err(bad_request(&format!(
                "profile `{profile_id}` is not registered"
            )));
        }
    }
    let forward_body = json!({
        "profile_id": profile_id,
        "product_type": product_type,
        "profile_version": profile_version,
        "effective_from": effective_from.to_string(),
        "retroactive": retroactive,
    });
    let outcome: RegistryOutcome = app
        .registry
        .bind_applicability(&forward_body)
        .await
        .map_err(|e| bad_request(&e))?;
    let audit_seq = {
        let mut store = app.store.lock().expect("store poisoned");
        store
            .bind_applicability(binding.clone(), outcome.via())
            .map_err(store_error)?
            .seq
    };
    let mut body = serde_json::to_value(&binding).expect("binding records are serde data");
    if let Some(m) = body.as_object_mut() {
        m.insert("via".into(), json!(outcome.mode.as_str()));
        if let Some(detail) = &outcome.detail {
            if outcome.mode == crate::registry::RegistryMode::Registry {
                m.insert("registry_response".into(), json!(detail));
            } else {
                m.insert("detail".into(), json!(detail));
            }
        }
        m.insert("audit_seq".into(), json!(audit_seq));
    }
    Ok(stamped(StatusCode::CREATED, &body, now))
}

/// GET /admin/applicability?product_type=&at= — locally recorded
/// bindings in force at `at`.
async fn applicability_query(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let at = parse_at(&params)?;
    let as_of = at.unwrap_or_else(Timestamp::now);
    let Some(subject) = opt_query(&params, "product_type") else {
        return Err(bad_request("`product_type` is required"));
    };
    let bindings = {
        let store = app.store.lock().expect("store poisoned");
        store
            .bindings_for(&subject)
            .into_iter()
            .filter(|b| b.applies_at(as_of))
            .cloned()
            .collect::<Vec<BindingRecord>>()
    };
    Ok(stamped(
        StatusCode::OK,
        &json!({
            "product_type": subject,
            "count": bindings.len(),
            "bindings": bindings,
        }),
        as_of,
    ))
}

/// GET /admin/log — the append-only audit log (admin, paged).
async fn admin_log(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, Response> {
    if let Some(deny) = require_admin(&app, &headers) {
        return Ok(deny);
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(10_000);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let view = {
        let store = app.store.lock().expect("store poisoned");
        store.log_json(limit, offset)
    };
    Ok(stamped(StatusCode::OK, &view, Timestamp::now()))
}

// ---------------------------------------------------------------------------
// Route wiring
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/keyring", get(keyring))
        .route("/passports", post(create_passport).get(list_passports))
        .route("/passports/{id}", get(get_passport))
        .route("/passports/{id}/events", post(append_event))
        .route("/passports/{id}/pack", post(mint_pack))
        .route("/passports/{id}/verdict", get(passport_verdict))
        .route("/admin/profiles", post(register_profile).get(list_profiles))
        .route(
            "/admin/applicability",
            post(bind_applicability).get(applicability_query),
        )
        .route("/admin/log", get(admin_log))
        .with_state(app)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let bind = config.bind;
    let app = Arc::new(AppState::new(config)?);
    let listener = TcpListener::bind(bind).await?;
    eprintln!("unidpp-issuer listening on http://{bind}");
    axum::serve(listener, router(app)).await
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    /// The bound address.
    pub addr: SocketAddr,
    /// `http://host:port` base URL.
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Spawn with a config (the bind address is replaced by an
    /// ephemeral loopback port).
    pub async fn spawn(mut config: Config) -> std::io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        config.bind = addr;
        let app = Arc::new(AppState::new(config)?);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-issuer: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    /// Stop the server and wait until its listener is released.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (handler-adjacent pure logic)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_codes_and_names() {
        assert_eq!(parse_capability("S0").unwrap(), CapabilityClass::Silent);
        assert_eq!(parse_capability("s3").unwrap(), CapabilityClass::Connected);
        assert_eq!(
            parse_capability("passive-auth").unwrap(),
            CapabilityClass::PassiveAuth
        );
        let err = parse_capability("S4").unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let err = parse_capability("wat").unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn derived_passport_ids_are_deterministic_per_moment() {
        let id = ProductIdentifier::parse("gtin:4006381333931").unwrap();
        let a = derive_passport_id(&id, Timestamp::from_secs(1_800_000_000));
        let b = derive_passport_id(&id, Timestamp::from_secs(1_800_000_000));
        let c = derive_passport_id(&id, Timestamp::from_secs(1_800_000_001));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.as_str().starts_with("urn:unidpp:passport:iss-"));
    }

    #[test]
    fn event_signatures_audit_against_the_anchor() {
        let app = AppState::new(Config::default()).unwrap();
        let record = {
            let mut store = app.store.lock().unwrap();
            let document = Passport::mint(MintOptions {
                id: "gtin:4006381333931".into(),
                granularity: None,
                type_ref: None,
                capability: "S1".into(),
                eo_id: Some("eo-t".into()),
                resolver_uri: None,
                passport_id: Some("urn:unidpp:passport:audit-1".into()),
                valid_from: None,
                valid_to: None,
            })
            .unwrap();
            let mut record = PassportRecord {
                document,
                config: vec![],
            };
            let event = TypedEvent::new(
                0,
                Timestamp::from_secs(1_800_000_000),
                "issuing authority",
                "eo-t",
                EventType::Issuance,
                default_payload(EventType::Issuance).unwrap(),
                TrustMarker::Attested,
            )
            .unwrap();
            let body = event.canonical_body().unwrap();
            let sig = sign_event(app.config.keyring.event_key(), 0, &body).unwrap();
            record.document.log.append(event, None, None).unwrap();
            record.document.event_signatures.push(sig);
            store.create_passport(record.clone()).unwrap();
            record
        };
        let audit = audit_event_signatures(&record, app.config.keyring.event_key());
        assert_eq!(audit["total"], 1);
        assert_eq!(audit["verified"], 1);
        assert_eq!(audit["failures"].as_array().unwrap().len(), 0);

        // A tampered signature value fails real verification.
        let mut bad = record.clone();
        bad.document.event_signatures[0].signature = hex_encode(&[0u8; 64]);
        let audit = audit_event_signatures(&bad, app.config.keyring.event_key());
        assert_eq!(audit["verified"], 0);
        assert_eq!(audit["failures"].as_array().unwrap().len(), 1);

        // A signature naming a missing seq fails loudly.
        let mut ghost = record;
        ghost.document.event_signatures[0].seq = 9;
        let audit = audit_event_signatures(&ghost, app.config.keyring.event_key());
        assert_eq!(audit["verified"], 0);
    }

    #[test]
    fn passport_view_keeps_cli_compatibility_and_adds_the_manifest() {
        let app = AppState::new(Config::default()).unwrap();
        let record = {
            let mut store = app.store.lock().unwrap();
            let document = Passport::mint(MintOptions {
                id: "sgtin:4006381333931+21+SN7".into(),
                granularity: Some(Granularity::Item),
                type_ref: Some("battery-li-ion".into()),
                capability: "S1".into(),
                eo_id: Some("eo-t".into()),
                resolver_uri: None,
                passport_id: Some("urn:unidpp:passport:view-1".into()),
                valid_from: None,
                valid_to: None,
            })
            .unwrap();
            let record = PassportRecord {
                document,
                config: vec!["urn:unidpp:profile:test".into()],
            };
            store.create_passport(record.clone()).unwrap();
            record
        };
        let view = passport_view(&record, None);
        assert_eq!(view["schema"], unidpp_cli::passport::SCHEMA);
        assert_eq!(view["config"][0], "urn:unidpp:profile:test");
        assert_eq!(view["status"], "issued");
        assert_eq!(view["log_head"], Value::Null);
        // CLI compatibility: the view round-trips through the CLI's
        // own document parser (unknown manifest fields are ignored).
        let text = serde_json::to_string_pretty(&view).unwrap();
        let back = Passport::from_json(&text).unwrap();
        assert_eq!(back.passport_id, record.document.passport_id);
        assert_eq!(back.log, record.document.log);
    }

    #[test]
    fn stamping_adds_the_as_of_fields() {
        let resp = stamped(
            StatusCode::OK,
            &json!({"a": 1}),
            Timestamp::from_secs(1_700_000_000),
        );
        let (parts, _body) = resp.into_parts();
        let as_of = parts
            .headers
            .get("x-as-of")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert_eq!(as_of, "2023-11-14T22:13:20Z");
    }
}
