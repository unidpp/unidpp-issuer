//! Integration tests: real HTTP against issuer servers spawned on
//! ephemeral ports (plus, for the admin-forwarding scenarios, a real
//! `unidpp-registry` instance). Covers the passport lifecycle
//! end-to-end: create → append signed events (I6 rejection included)
//! → pack (QR budget enforcement) → verdict, journal replay across a
//! restart, admin forwarding (registry / unreachable / fixtures), auth
//! gating, and the CLI round-trip (the `unidpp` command library minting
//! and verifying against the server's own anchors).

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};
use unidpp_issuer::http::{json_request, request, HttpResponse, Url};
use unidpp_issuer::{Config, Keyring, TestServer};
use unidpp_signatif::keyring::KeyId;
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};

// ---------------------------------------------------------------------------
// Support
// ---------------------------------------------------------------------------

async fn spawn_open() -> TestServer {
    TestServer::spawn(Config::default())
        .await
        .expect("spawn issuer")
}

async fn spawn_seeded(seed: &str, state_file: Option<PathBuf>) -> TestServer {
    let config = Config {
        keyring: Keyring::dev(Some(seed)).expect("dev keyring"),
        state_file,
        ..Config::default()
    };
    TestServer::spawn(config).await.expect("spawn issuer")
}

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unidpp-issuer-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join(name)
}

async fn post(base: &str, path: &str, body: &Value, token: Option<&str>) -> HttpResponse {
    json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        token,
        Duration::from_secs(10),
    )
    .await
    .expect("http request")
}

async fn get(base: &str, path: &str) -> HttpResponse {
    json_request(
        "GET",
        &format!("{base}{path}"),
        None,
        None,
        Duration::from_secs(10),
    )
    .await
    .expect("http request")
}

fn json_of(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.body_string()).expect("response JSON")
}

/// Client-side verification of one recorded event signature against the
/// issuer's published anchor (what a verifier does with the document).
fn verify_event_signature(
    sig: &Value,
    event: &Value,
    anchor_hex: &str,
    suite: Suite,
) -> Result<(), String> {
    let anchor = unidpp_signatif::keyring::PublicKey::from_bytes(
        &unidpp_cli::encoding::hex_decode(anchor_hex).expect("anchor hex"),
    )
    .map_err(|e| e.to_string())?;
    let event: unidpp_event::TypedEvent =
        serde_json::from_value(event.clone()).map_err(|e| e.to_string())?;
    let body = event.canonical_body().map_err(|e| e.to_string())?;
    let slot = SignatureSlot {
        suite,
        key_id: KeyId::new(sig["key_id"].as_str().expect("key_id")).map_err(|e| e.to_string())?,
        signature: Some(
            unidpp_cli::encoding::hex_decode(sig["signature"].as_str().expect("signature"))
                .map_err(|e| format!("signature hex: {e}"))?,
        ),
    };
    slot.verify(SigningDomain::ArtifactEvent, &body, &anchor)
        .map_err(|e| e.to_string())
}

fn create_body() -> Value {
    let mut m = serde_json::Map::new();
    m.insert("identity".into(), json!("sgtin:4006381333931+21+SN7"));
    m.insert("type_ref".into(), json!("battery-li-ion"));
    m.insert(
        "config".into(),
        json!(["urn:unidpp:profile:eu-espr-battery-v3"]),
    );
    m.insert("capability".into(), json!("S1"));
    m.insert("eo_id".into(), json!("eo-integration"));
    Value::Object(m)
}

async fn create_default(base: &str) -> String {
    let resp = post(base, "/passports", &create_body(), None).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    json_of(&resp)["passport_id"]
        .as_str()
        .expect("passport id")
        .to_string()
}

// ---------------------------------------------------------------------------
// Creation and reads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_passports_enumerates_every_created_passport() {
    let server = spawn_open().await;
    let base = &server.base_url;

    let empty = json_of(&get(base, "/passports").await);
    assert_eq!(empty["count"], 0, "a fresh issuer lists zero passports");

    let first = json_of(&post(base, "/passports", &create_body(), None).await);
    let second = json_of(&post(base, "/passports", &create_body(), None).await);
    let ids = [
        first["passport_id"].as_str().unwrap(),
        second["passport_id"].as_str().unwrap(),
    ];

    let listing = json_of(&get(base, "/passports").await);
    assert_eq!(listing["count"], 2);
    assert_eq!(listing["limit"], 100, "the default window");
    assert_eq!(listing["offset"], 0);
    // Pagination: a window into the register, count stays the TOTAL.
    let page = json_of(&get(base, "/passports?limit=1").await);
    assert_eq!(page["count"], 2);
    assert_eq!(page["limit"], 1);
    assert_eq!(page["passports"].as_array().unwrap().len(), 1);
    let second = json_of(&get(base, "/passports?limit=1&offset=1").await);
    assert_eq!(second["count"], 2);
    assert_eq!(second["passports"].as_array().unwrap().len(), 1);
    assert_ne!(
        page["passports"][0]["passport_id"], second["passports"][0]["passport_id"],
        "offset advances the window"
    );
    let beyond = json_of(&get(base, "/passports?offset=99").await);
    assert_eq!(beyond["count"], 2);
    assert_eq!(
        beyond["passports"].as_array().unwrap().len(),
        0,
        "past the end: empty page"
    );
    // The cap and the contract violations.
    let capped = json_of(&get(base, "/passports?limit=9999").await);
    assert_eq!(capped["limit"], 500, "the hard cap");
    assert_eq!(get(base, "/passports?limit=zero").await.status, 400);
    let listed: Vec<&str> = listing["passports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["passport_id"].as_str().unwrap())
        .collect();
    // Sorted by id (the store's stable order), every row carries the
    // subject fields.
    let mut sorted = ids.to_vec();
    sorted.sort();
    assert_eq!(listed, sorted, "listed in id order");
    for row in listing["passports"].as_array().unwrap() {
        assert!(row["product_id"].is_string());
        assert_eq!(row["capability"], "passive-auth", "the model's wire token");
        assert!(row["eo_id"].is_string());
        assert_eq!(row["events"], 0);
    }
}

#[tokio::test]
async fn create_passport_returns_id_and_empty_log() {
    let server = spawn_open().await;
    let base = &server.base_url;

    // Discovery, health, keyring.
    let resp = get(base, "/").await;
    assert_eq!(resp.status, 200);
    let doc = json_of(&resp);
    assert_eq!(doc["service"], "unidpp-issuer");
    assert_eq!(doc["keyring_mode"], "seeded-dev");
    assert_eq!(
        doc["signatures"]["events"],
        "ed25519 (SIGNATIF infrastructure suite)"
    );
    assert_eq!(get(base, "/healthz").await.status, 200);
    let keyring = json_of(&get(base, "/keyring").await);
    assert_eq!(keyring["mode"], "seeded-dev");
    // public_serialized is the suite-certain ANCHOR: suite:public-hex
    // that verify --anchor parses — never the fingerprint grammar.
    let pack_pub = keyring["roles"]["pack"]["public"].as_str().unwrap();
    let pack_ser = keyring["roles"]["pack"]["public_serialized"]
        .as_str()
        .unwrap();
    let (suite_token, suite_hex) = pack_ser.split_once(':').expect("suite:hex");
    assert_eq!(suite_token, "ecdsa-p256");
    assert_eq!(
        suite_hex, pack_pub,
        "the serialization carries the key bytes"
    );
    let event_ser = keyring["roles"]["event"]["public_serialized"]
        .as_str()
        .unwrap();
    assert!(
        !event_ser.contains(keyring["roles"]["event"]["key_id"].as_str().unwrap()),
        "not the fingerprint grammar"
    );
    assert!(keyring["roles"]["event"]["key_id"]
        .as_str()
        .unwrap()
        .starts_with("k-"));
    assert_eq!(keyring["roles"]["pack"]["suite"], "ecdsa-p256");

    // Create.
    let resp = post(base, "/passports", &create_body(), None).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    let id = created["passport_id"].as_str().unwrap().to_string();
    assert!(id.starts_with("urn:unidpp:passport:iss-"));
    assert_eq!(created["schema"], "unidpp/passport@1");
    assert_eq!(created["granularity"], "item");
    assert_eq!(created["capability"], "passive-auth");
    assert_eq!(
        created["config"][0],
        "urn:unidpp:profile:eu-espr-battery-v3"
    );
    assert_eq!(created["log"]["len"], 0);
    assert_eq!(created["audit_seq"], 1);
    assert!(unidpp_model::Timestamp::parse(resp.header("x-as-of").unwrap()).is_ok());

    // The GET view is CLI-compatible (the `unidpp` binary can load it).
    let resp = get(base, &format!("/passports/{id}")).await;
    assert_eq!(resp.status, 200);
    let view = json_of(&resp);
    assert_eq!(view["passport_id"], id.as_str());
    assert_eq!(view["status"], "issued");
    assert_eq!(view["log_head"], Value::Null);
    assert_eq!(view["config"][0], "urn:unidpp:profile:eu-espr-battery-v3");
    let passport = unidpp_cli::passport::Passport::from_json(&resp.body_string())
        .expect("CLI parses the GET view");
    assert_eq!(passport.passport_id.as_str(), id);
    assert!(passport.log.is_empty());

    // Validation failures.
    let mut bad = create_body().clone();
    bad["identity"] = Value::Null;
    assert_eq!(post(base, "/passports", &bad, None).await.status, 400);
    let mut bad = create_body().clone();
    bad["identity"] = json!("not an identifier");
    assert_eq!(post(base, "/passports", &bad, None).await.status, 400);
    let mut bad = create_body().clone();
    bad["capability"] = json!("S9");
    assert_eq!(post(base, "/passports", &bad, None).await.status, 400);
    let mut bad = create_body().clone();
    bad["granularity"] = json!("model");
    assert_eq!(post(base, "/passports", &bad, None).await.status, 400);
    let mut bad = create_body().clone();
    bad["config"] = json!(42);
    assert_eq!(post(base, "/passports", &bad, None).await.status, 400);

    // Duplicate passport id conflicts.
    let mut dup = create_body().clone();
    dup["passport_id"] = json!(id);
    assert_eq!(post(base, "/passports", &dup, None).await.status, 409);

    // No-information 404: identical bytes for unknown passports.
    let unknown = get(base, "/passports/urn:unidpp:passport:nope").await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.body_string(), unidpp_issuer::api::NOT_FOUND_BODY);
    // Bad `at`.
    assert_eq!(
        get(base, &format!("/passports/{id}?at=nonsense"))
            .await
            .status,
        400
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Event appends: signatures, trust markers, I6
// ---------------------------------------------------------------------------

#[tokio::test]
async fn append_events_sign_and_reject_illegal_transitions() {
    let server = spawn_open().await;
    let base = &server.base_url;
    let id = create_default(base).await;
    let anchor_hex = json_of(&get(base, "/keyring").await)["roles"]["event"]["public"]
        .as_str()
        .unwrap()
        .to_string();

    // First event: issuance (default payload, no --data needed).
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "issuance"}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let ev = json_of(&resp);
    assert_eq!(ev["seq"], 0);
    assert_eq!(ev["trust"], "attested");
    assert_eq!(ev["actor_role"], "issuing authority");
    assert_eq!(ev["actor_id"], "eo-integration");
    assert_eq!(ev["status"], "issued");
    assert!(ev["log_head"].as_str().unwrap().len() >= 16);
    let sig = ev["signature"].clone();
    assert_eq!(sig["suite"], "ed25519");

    // The signature verifies against the published anchor.
    let view = json_of(&get(base, &format!("/passports/{id}")).await);
    let sealed0 = &view["log"]["sealed"][0]["event"];
    verify_event_signature(&sig, sealed0, &anchor_hex, Suite::Ed25519)
        .expect("server signature verifies against the anchor");

    // Install event (typed payload, bare body form).
    let install = json!({
        "type": "install",
        "actor": "installer-1",
        "data": {"target": {"Open": {
            "link_type": "installation",
            "other": "urn:unidpp:passport:host-1",
            "direction": "incoming",
            "interval": {"from": "2026-09-07T00:00:00Z", "to": null},
            "binding": null
        }}}
    });
    let resp = post(base, &format!("/passports/{id}/events"), &install, None).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let ev = json_of(&resp);
    assert_eq!(ev["seq"], 1);
    assert_eq!(ev["event_type"], "install");
    assert_eq!(ev["actor_role"], "installer / repairer");

    // Custody transfer (wrapped body form, explicit role).
    let custody = json!({
        "type": "custody.transfer",
        "data": {"CustodyTransfer": {"from": "eo-integration", "to": "alice", "counterparty_signed": true}},
        "actor_role": "custodian"
    });
    let resp = post(base, &format!("/passports/{id}/events"), &custody, None).await;
    assert_eq!(resp.status, 201);
    let view = json_of(&get(base, &format!("/passports/{id}")).await);
    assert_eq!(view["custodian"], "alice");
    assert_eq!(view["events"], 3);
    assert_eq!(view["log"]["sealed"].as_array().unwrap().len(), 3);
    assert_eq!(view["event_signatures"].as_array().unwrap().len(), 3);

    // Legal status transition: issued -> suspended.
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "status.change", "data": {"from": "issued", "to": "suspended", "authority": "reg-1"}}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["status"], "suspended");

    // I6: abstractly illegal transition (suspended -> suspended).
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "status.change", "data": {"from": "suspended", "to": "suspended", "authority": "reg-1"}}),
        None,
    )
    .await;
    assert_eq!(resp.status, 409);
    assert!(json_of(&resp)["error"].as_str().unwrap().contains("I6"));

    // I6: legal transition claimed from a stale state (log is suspended).
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "status.change", "data": {"from": "issued", "to": "invalidated", "authority": "reg-1"}}),
        None,
    )
    .await;
    assert_eq!(resp.status, 409);

    // Unsigned append: trust marker downgrades honestly.
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "correction", "sign": false, "data": {"field": "mass_kg", "prior_value": "1.0", "new_value": "1.1", "reason": "typo"}}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    let ev = json_of(&resp);
    assert_eq!(ev["trust"], "unsigned");
    assert_eq!(ev["signature"], Value::Null);

    // Recall drives the safety flag.
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "recall.campaign", "data": {"campaign": "R-9", "predicate": "Any"}}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["safety"], "recall-active");

    // Validation: unknown type token, bad payload shape, bad `at`,
    // missing data for a class that needs it, unknown passport.
    let mut bad = json!({"type": "teleport"});
    assert_eq!(
        post(base, &format!("/passports/{id}/events"), &bad, None)
            .await
            .status,
        400
    );
    bad = json!({"type": "custody.transfer", "data": {"field": "f"}});
    assert_eq!(
        post(base, &format!("/passports/{id}/events"), &bad, None)
            .await
            .status,
        400
    );
    bad = json!({"type": "custody.transfer", "at": "not-a-time", "data": {"from": "a", "to": "b", "counterparty_signed": true}});
    assert_eq!(
        post(base, &format!("/passports/{id}/events"), &bad, None)
            .await
            .status,
        400
    );
    bad = json!({"type": "custody.transfer"});
    assert_eq!(
        post(base, &format!("/passports/{id}/events"), &bad, None)
            .await
            .status,
        400
    );
    bad = json!({"type": "issuance"});
    assert_eq!(
        post(
            base,
            "/passports/urn:unidpp:passport:ghost/events",
            &bad,
            None
        )
        .await
        .status,
        404
    );
    assert_eq!(
        post(
            base,
            "/passports/urn:unidpp:passport:ghost/events",
            &bad,
            None
        )
        .await
        .body_string(),
        unidpp_issuer::api::NOT_FOUND_BODY
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Pack minting and the QR budget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pack_minting_signs_and_enforces_the_budget() {
    let server = spawn_seeded("budget-seed", None).await;
    let base = &server.base_url;
    let id = create_default(base).await;
    post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "issuance"}),
        None,
    )
    .await;

    let anchor_hex = json_of(&get(base, "/keyring").await)["roles"]["pack"]["public"]
        .as_str()
        .unwrap()
        .to_string();

    // Default budget: real signature, real verification.
    let resp = post(base, &format!("/passports/{id}/pack"), &json!({}), None).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let pack = json_of(&resp);
    assert_eq!(pack["encoding"], "hex");
    assert_eq!(pack["signature"]["suite"], "ecdsa-p256");
    assert_eq!(pack["anchor"], anchor_hex.as_str());
    assert!(pack["bytes"].as_u64().unwrap() > 0);
    assert!(pack["qr_version"].as_u64().unwrap() <= 40);

    // Decode + verify through the CLI pipeline with the pinned anchor.
    let bytes = unidpp_cli::encoding::hex_decode(pack["pack"].as_str().unwrap()).unwrap();
    let anchor = unidpp_signatif::keyring::PublicKey::from_bytes(
        &unidpp_cli::encoding::hex_decode(&anchor_hex).unwrap(),
    )
    .unwrap();
    let now = unidpp_model::Timestamp::now();
    let outcome = unidpp_cli::commands::verify::verify_pack(
        &bytes,
        Some(&anchor),
        now,
        unidpp_cli::commands::verify::DEFAULT_MAX_AGE_SECS,
    );
    assert_eq!(
        outcome.grade,
        unidpp_cli::report::Grade::Pass,
        "{:#?}",
        outcome.findings
    );
    assert_eq!(
        outcome.trust_marker,
        Some(unidpp_model::TrustMarker::Attested)
    );

    // Explicit workable budget and base64 encoding.
    let resp = post(
        base,
        &format!("/passports/{id}/pack"),
        &json!({"budget": "qr-v15-M", "encoding": "base64"}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let pack = json_of(&resp);
    assert_eq!(pack["encoding"], "base64");
    assert_eq!(pack["qr_version"], 15);
    let bytes = unidpp_cli::encoding::base64_decode(pack["pack"].as_str().unwrap()).unwrap();
    let outcome = unidpp_cli::commands::verify::verify_pack(
        &bytes,
        Some(&anchor),
        now,
        unidpp_cli::commands::verify::DEFAULT_MAX_AGE_SECS,
    );
    assert_eq!(outcome.grade, unidpp_cli::report::Grade::Pass);

    // Unsigned pack: no signature slots.
    let resp = post(
        base,
        &format!("/passports/{id}/pack"),
        &json!({"sign": false}),
        None,
    )
    .await;
    let pack = json_of(&resp);
    assert_eq!(pack["signature"], Value::Null);

    // Over-budget: a tiny carrier rejects loudly (413), never truncates.
    let resp = post(
        base,
        &format!("/passports/{id}/pack"),
        &json!({"budget": "qr-v3-M"}),
        None,
    )
    .await;
    assert_eq!(resp.status, 413, "{}", resp.body_string());
    let error = json_of(&resp)["error"].as_str().unwrap().to_string();
    assert!(
        error.contains("QR carrier holds at most") || error.contains("capacity"),
        "{error}"
    );

    // Validation: bad budget grammar, bad encoding, unknown passport.
    assert_eq!(
        post(
            base,
            &format!("/passports/{id}/pack"),
            &json!({"budget": "qr-v99-M"}),
            None
        )
        .await
        .status,
        400
    );
    assert_eq!(
        post(
            base,
            &format!("/passports/{id}/pack"),
            &json!({"encoding": "rot13"}),
            None
        )
        .await
        .status,
        400
    );
    assert_eq!(
        post(
            base,
            "/passports/urn:unidpp:passport:ghost/pack",
            &json!({}),
            None
        )
        .await
        .status,
        404
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// The verdict endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verdict_runs_the_full_pipeline_with_coverage() {
    let server = spawn_open().await;
    let base = &server.base_url;
    let id = create_default(base).await;
    post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "issuance"}),
        None,
    )
    .await;
    post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "custody.transfer", "data": {"from": "eo-integration", "to": "bob", "counterparty_signed": true}}),
        None,
    )
    .await;

    let resp = get(base, &format!("/passports/{id}/verdict")).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    let verdict = json_of(&resp);
    assert_eq!(verdict["passport_id"], id.as_str());
    assert_eq!(verdict["reading_answered"], "current-state");
    // Log verdict: anchored at its own head with fresh evidence.
    assert_eq!(verdict["log"]["outcome"], "Pass");
    assert_eq!(verdict["log"]["trust_marker"], "log-anchored");
    assert_eq!(verdict["log"]["current_state"]["status"], "issued");
    assert_eq!(verdict["log"]["current_state"]["custodian"], "bob");
    // Event signatures: re-verified server-side against the anchor.
    assert_eq!(verdict["event_signatures"]["total"], 2);
    assert_eq!(verdict["event_signatures"]["verified"], 2);
    assert_eq!(
        verdict["event_signatures"]["failures"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    // Tier-A leg: the pack an officer would scan verifies Pass with
    // complete carrier coverage.
    assert_eq!(verdict["tier_a"]["grade"], "pass");
    assert_eq!(verdict["tier_a"]["exit_code"], 0);
    assert_eq!(verdict["tier_a"]["trust_marker"], "attested");
    let coverage = &verdict["tier_a"]["coverage"];
    assert_eq!(coverage["required"].as_array().unwrap().len(), 10);
    assert_eq!(coverage["present"].as_array().unwrap().len(), 10);
    assert!(
        verdict["tier_a"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["check"] == "signature/ecdsa-p256/slot-1" && f["grade"] == "Pass"),
        "{:#?}",
        verdict["tier_a"]["findings"]
    );
    // Config vector resolution (nothing registered yet).
    assert_eq!(
        verdict["config"]["vector"][0],
        "urn:unidpp:profile:eu-espr-battery-v3"
    );
    assert_eq!(verdict["config"]["resolved"].as_array().unwrap().len(), 0);
    assert_eq!(
        verdict["config"]["unresolved"][0],
        "urn:unidpp:profile:eu-espr-battery-v3"
    );

    // Register the profile: the config vector resolves, the coverage
    // report gains the profile's data points (absent → reported).
    let resp = post(
        base,
        "/admin/profiles",
        &json!({
            "profile_id": "urn:unidpp:profile:eu-espr-battery-v3",
            "definition": "EU ESPR battery passport lens",
            "version": "1.0.0",
            "data_points": ["ferin:eu/battery-state", "ferin:eu/carbon-footprint"]
        }),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["via"], "fixtures");

    let verdict = json_of(&get(base, &format!("/passports/{id}/verdict")).await);
    assert_eq!(
        verdict["config"]["resolved"][0]["config"],
        "urn:unidpp:profile:eu-espr-battery-v3"
    );
    assert_eq!(
        verdict["config"]["resolved"][0]["data_points"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Static freshness semantics never go stale.
    let resp = get(
        base,
        &format!("/passports/{id}/verdict?at=2030-01-01T00:00:00Z&max_age=0"),
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(json_of(&resp)["tier_a"]["freshness"], "fresh");

    // Unknown passport: no-information 404; bad max_age: 400.
    assert_eq!(
        get(base, "/passports/urn:unidpp:passport:ghost/verdict")
            .await
            .status,
        404
    );
    assert_eq!(
        get(base, &format!("/passports/{id}/verdict?max_age=soon"))
            .await
            .status,
        400
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Journal replay across a restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn journal_replays_across_a_restart() {
    let state = temp_path("replay-audit.jsonl");
    let _ = std::fs::remove_file(&state);
    let seed = "replay-seed";

    let id = {
        let server = spawn_seeded(seed, Some(state.clone())).await;
        let base = &server.base_url;
        let id = create_default(base).await;
        post(
            base,
            &format!("/passports/{id}/events"),
            &json!({"type": "issuance"}),
            None,
        )
        .await;
        post(
            base,
            &format!("/passports/{id}/events"),
            &json!({"type": "custody.transfer", "data": {"from": "a", "to": "b", "counterparty_signed": true}}),
            None,
        )
        .await;
        let before = json_of(&get(base, &format!("/passports/{id}")).await);
        assert_eq!(before["events"], 2);
        server.stop().await;
        id
    };

    // Restart on the same journal: the same log head, the same
    // signatures, the audit log continues.
    let server = spawn_seeded(seed, Some(state.clone())).await;
    let base = &server.base_url;
    let after = json_of(&get(base, &format!("/passports/{id}")).await);
    assert_eq!(after["events"], 2);
    assert_eq!(after["log_head"], after["log_head"]); // present
    assert!(after["log_head"].as_str().unwrap().len() == 64);
    assert_eq!(after["event_signatures"].as_array().unwrap().len(), 2);
    // The replayed chain verifies and the client can still check the
    // signatures against the (seed-derived, stable) anchor.
    let anchor_hex = json_of(&get(base, "/keyring").await)["roles"]["event"]["public"]
        .as_str()
        .unwrap()
        .to_string();
    let sig = &after["event_signatures"][0];
    let sealed0 = &after["log"]["sealed"][0]["event"];
    verify_event_signature(sig, sealed0, &anchor_hex, Suite::Ed25519)
        .expect("replayed signature still verifies");

    // New mutations continue the audit sequence.
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "correction", "data": {"field": "x", "prior_value": "1", "new_value": "2", "reason": "r"}}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201);
    assert_eq!(json_of(&resp)["audit_seq"], 4);
    let log = json_of(&get(base, "/admin/log?limit=10").await);
    assert_eq!(log["total"], 4);

    server.stop().await;
    let _ = std::fs::remove_file(&state);
}

// ---------------------------------------------------------------------------
// Admin: registry forwarding, fixtures fallback, auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_forwards_to_a_live_registry_and_falls_back_to_fixtures() {
    // A real registry instance.
    let registry = unidpp_registry::TestServer::spawn(unidpp_registry::Config::default())
        .await
        .expect("spawn registry");

    // Issuer pointed at it.
    let config = Config {
        registry_url: Some(registry.base_url.clone()),
        ..Config::default()
    };
    let server = TestServer::spawn(config).await.expect("spawn issuer");
    let base = &server.base_url;

    let resp = post(
        base,
        "/admin/profiles",
        &json!({
            "profile_id": "eu-espr-battery-v3",
            "definition": "EU ESPR battery passport lens",
            "version": "1.0.0",
            "register_id": "unidpp-dev",
            "data_points": ["ferin:eu/battery-state"]
        }),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    assert_eq!(created["via"], "registry");
    assert!(created["registry_response"]
        .as_str()
        .unwrap()
        .contains("eu-espr-battery-v3"));
    // The registry actually holds the item.
    let item = json_of(&get(&registry.base_url, "/profiles/eu-espr-battery-v3").await);
    assert_eq!(item["identifier"], "eu-espr-battery-v3");
    assert_eq!(item["item_class"], "profile");

    let resp = post(
        base,
        "/admin/applicability",
        &json!({"profile_id": "eu-espr-battery-v3", "product_type": "battery-li-ion", "retroactive": true}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["via"], "registry");

    // Duplicate version: the live registry rejects the re-registration
    // first, and the rejection surfaces verbatim (nothing is journaled).
    let resp = post(
        base,
        "/admin/profiles",
        &json!({"profile_id": "eu-espr-battery-v3", "definition": "again", "version": "1.0.0"}),
        None,
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.body_string());
    assert!(json_of(&resp)["error"]
        .as_str()
        .unwrap()
        .contains("already registered"));

    // Local views.
    let profiles = json_of(&get(base, "/admin/profiles").await);
    assert_eq!(profiles["count"], 1);
    let bindings = json_of(&get(base, "/admin/applicability?product_type=battery-li-ion").await);
    assert_eq!(bindings["count"], 1);
    assert_eq!(bindings["bindings"][0]["profile_id"], "eu-espr-battery-v3");
    assert_eq!(get(base, "/admin/applicability").await.status, 400);
    server.stop().await;
    registry.stop().await;

    // An issuer pointed at an unreachable registry degrades to fixtures.
    let config = Config {
        registry_url: Some("http://127.0.0.1:1".to_string()),
        ..Config::default()
    };
    let server = TestServer::spawn(config).await.expect("spawn issuer");
    let resp = post(
        &server.base_url,
        "/admin/profiles",
        &json!({"profile_id": "jp-battery", "definition": "JP lens", "version": "1.0.0"}),
        None,
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let created = json_of(&resp);
    assert_eq!(created["via"], "unreachable");
    assert!(created["detail"]
        .as_str()
        .unwrap()
        .contains("not reachable"));
    // Binding to an unknown profile is rejected.
    assert_eq!(
        post(
            &server.base_url,
            "/admin/applicability",
            &json!({"profile_id": "nope", "product_type": "t"}),
            None
        )
        .await
        .status,
        400
    );
    server.stop().await;
}

#[tokio::test]
async fn admin_token_guards_mutations() {
    let config = Config {
        admin_token: Some("secret-token".to_string()),
        ..Config::default()
    };
    let server = TestServer::spawn(config).await.expect("spawn issuer");
    let base = &server.base_url;

    // Reads stay public.
    assert_eq!(get(base, "/keyring").await.status, 200);
    assert_eq!(get(base, "/healthz").await.status, 200);

    // Mutations need the bearer token; wrong token is as good as none.
    assert_eq!(
        post(base, "/passports", &create_body(), None).await.status,
        401
    );
    assert_eq!(
        post(base, "/passports", &create_body(), Some("wrong"))
            .await
            .status,
        401
    );
    assert_eq!(
        post(
            base,
            "/admin/profiles",
            &json!({"profile_id": "p", "definition": "d"}),
            None
        )
        .await
        .status,
        401
    );
    assert_eq!(get(base, "/admin/log").await.status, 401);
    assert_eq!(get(base, "/admin/profiles").await.status, 401);

    let resp = post(base, "/passports", &create_body(), Some("secret-token")).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let id = json_of(&resp)["passport_id"].as_str().unwrap().to_string();
    // Event append and pack under the token.
    let resp = post(
        base,
        &format!("/passports/{id}/events"),
        &json!({"type": "issuance"}),
        Some("secret-token"),
    )
    .await;
    assert_eq!(resp.status, 201);
    // Pack and verdict are reads/projections: public.
    assert_eq!(
        post(base, &format!("/passports/{id}/pack"), &json!({}), None)
            .await
            .status,
        201
    );
    assert_eq!(
        get(base, &format!("/passports/{id}/verdict")).await.status,
        200
    );
    assert_eq!(get(base, &format!("/passports/{id}")).await.status, 200);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// The CLI round-trip (issue → install/event → pack → verify)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cli_round_trip_issues_packs_and_verifies_offline() {
    let seed = "round-trip-seed";
    let server = spawn_seeded(seed, None).await;
    let base = &server.base_url;

    // Issue (identity, type ref, config vector, capability class).
    let id = create_default(base).await;
    // Event: install + custody, server-signed.
    let install = json!({
        "type": "install",
        "data": {"target": {"Open": {
            "link_type": "installation",
            "other": "urn:unidpp:passport:host-roundtrip",
            "direction": "incoming",
            "interval": {"from": "2026-09-07T00:00:00Z", "to": null},
            "binding": null
        }}}
    });
    assert_eq!(
        post(base, &format!("/passports/{id}/events"), &install, None)
            .await
            .status,
        201
    );
    assert_eq!(
        post(
            base,
            &format!("/passports/{id}/events"),
            &json!({"type": "custody.transfer", "data": {"from": "eo-integration", "to": "carol", "counterparty_signed": true}}),
            None
        )
        .await
        .status,
        201
    );

    // The officer side: fetch the document, drive the real CLI library.
    let view = get(base, &format!("/passports/{id}")).await;
    assert_eq!(view.status, 200);
    let passport_path = temp_path("roundtrip-passport.json");
    std::fs::write(&passport_path, view.body_string()).expect("write passport");

    let keyring = json_of(&get(base, "/keyring").await);
    let anchor_hex = keyring["roles"]["pack"]["public"]
        .as_str()
        .unwrap()
        .to_string();
    // The CLI signs with the raw seed bytes it is given; the server's
    // pack key derives from "unidpp-issuer/pack|<seed>", so passing that
    // exact material to --key reproduces the server's key.
    let cli_seed = format!("unidpp-issuer/pack|{seed}");
    let pack_path = temp_path("roundtrip-pack.hex");

    let args: Vec<String> = [
        "pack",
        "--passport",
        passport_path.to_str().unwrap(),
        "--key",
        &cli_seed,
        "--out",
        pack_path.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let code = unidpp_cli::commands::dispatch(&args).expect("pack dispatch");
    assert_eq!(code, 0, "CLI pack failed");

    // Verify the CLI-minted pack offline against the server's anchor.
    let args: Vec<String> = [
        "verify",
        pack_path.to_str().unwrap(),
        "--anchor",
        &anchor_hex,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let code = unidpp_cli::commands::dispatch(&args).expect("verify dispatch");
    assert_eq!(code, 0, "CLI verify of a CLI-minted pack must PASS");

    // Verify a SERVER-minted pack through the CLI: the officer flow.
    let resp = post(base, &format!("/passports/{id}/pack"), &json!({}), None).await;
    assert_eq!(resp.status, 201);
    let server_pack = json_of(&resp)["pack"].as_str().unwrap().to_string();
    let server_pack_path = temp_path("roundtrip-server-pack.hex");
    std::fs::write(&server_pack_path, &server_pack).expect("write pack");
    let args: Vec<String> = [
        "verify",
        server_pack_path.to_str().unwrap(),
        "--anchor",
        &anchor_hex,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let code = unidpp_cli::commands::dispatch(&args).expect("verify dispatch");
    assert_eq!(code, 0, "CLI verify of a server-minted pack must PASS");

    // The CLI can also load the document and append to it locally —
    // the GET view is a first-class `unidpp/passport@1` document.
    let passport =
        unidpp_cli::passport::Passport::load(&passport_path).expect("CLI loads the view");
    assert_eq!(passport.log.len(), 2);
    assert_eq!(passport.log.custodian().as_deref(), Some("carol"));

    let _ = std::fs::remove_file(&passport_path);
    let _ = std::fs::remove_file(&pack_path);
    let _ = std::fs::remove_file(&server_pack_path);
    server.stop().await;
}

// ---------------------------------------------------------------------------
// URL helper sanity through the public http module
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_module_round_trip_against_the_service() {
    let server = spawn_open().await;
    let url = Url::parse(&server.base_url).expect("base url");
    let resp = request(
        "GET",
        &Url {
            path_and_query: "/healthz".to_string(),
            ..url
        },
        &[],
        None,
        Duration::from_secs(5),
    )
    .await
    .expect("healthz");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body_string(), "ok");
    server.stop().await;
}
