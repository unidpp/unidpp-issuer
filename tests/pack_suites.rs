//! Sovereign pack-suite integration: the `/pack` endpoint under SM2,
//! under the P-256+SM2 co-signature, and the per-suite degradation a
//! partially-anchored verifier reads. Real HTTP against a real issuer
//! server; verification re-uses the CLI pipeline an officer's terminal
//! runs (`verify_pack_with_anchors`), never a parallel implementation.

use std::time::Duration;

use serde_json::{json, Value};
use unidpp_cli::commands::verify::{verify_pack, verify_pack_with_anchors, DEFAULT_MAX_AGE_SECS};
use unidpp_cli::encoding::hex_decode;
use unidpp_issuer::http::{json_request, HttpResponse};
use unidpp_issuer::keyring::{Keyring, PackSuites};
use unidpp_issuer::{Config, TestServer};
use unidpp_signatif::keyring::PublicKey;
use unidpp_signatif::sign::Suite;

// ---------------------------------------------------------------------------
// Support
// ---------------------------------------------------------------------------

async fn post(base: &str, path: &str, body: &Value) -> HttpResponse {
    json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        None,
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

async fn spawn(suites: &str) -> (TestServer, String) {
    let config = Config {
        keyring: Keyring::with_pack_suites(
            Some("pack-suites-it"),
            &PackSuites::parse(suites).expect("valid suite list"),
        )
        .expect("keyring"),
        ..Config::default()
    };
    let server = TestServer::spawn(config).await.expect("spawn issuer");
    let resp = post(
        &server.base_url,
        "/passports",
        &json!({
            "identity": "sgtin:4006381333931+21+PS-1",
            "granularity": "item",
            "type_ref": "e-bike",
            "capability": "S1"
        }),
    )
    .await;
    assert_eq!(resp.status, 201, "create failed: {}", resp.body_string());
    let id = json_of(&resp)["passport_id"]
        .as_str()
        .expect("passport id")
        .to_string();
    // A pack always follows at least the issuance event (the carrier's
    // log-head commitment pins it).
    let resp = post(
        &server.base_url,
        &format!("/passports/{id}/events"),
        &json!({ "type": "issuance" }),
    )
    .await;
    assert_eq!(resp.status, 201, "event append: {}", resp.body_string());
    (server, id)
}

async fn mint(server: &TestServer, id: &str, body: Value) -> HttpResponse {
    post(&server.base_url, &format!("/passports/{id}/pack"), &body).await
}

/// The pinned anchor for `suite` from the live `/keyring` document —
/// exactly the bytes a sovereign verifier pins.
async fn anchor_of(server: &TestServer, suite: Suite) -> PublicKey {
    let doc = json_of(&get(&server.base_url, "/keyring").await);
    let hex = doc["roles"]["pack"]["suites"][suite.as_str()]["public"]
        .as_str()
        .unwrap_or_else(|| panic!("no {suite} anchor in /keyring"))
        .to_string();
    PublicKey::from_bytes_in(suite, &hex_decode(&hex).expect("anchor hex")).expect("anchor decodes")
}

fn pack_now(doc: &Value) -> unidpp_model::Timestamp {
    doc["as_of"]
        .as_str()
        .and_then(|s| unidpp_model::Timestamp::parse(s).ok())
        .unwrap_or_else(unidpp_model::Timestamp::now)
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sm2_only_deployment_mints_and_verifies_under_sm2() {
    let (server, id) = spawn("sm2").await;
    let resp = mint(&server, &id, json!({})).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&resp);
    assert_eq!(doc["signature"]["suite"], "sm2");
    assert_eq!(doc["anchors"]["sm2"].as_str().map(str::len), Some(130));

    // The officer's terminal: decode the hex pack, verify against the
    // SM2 anchor.
    let bytes = hex_decode(doc["pack"].as_str().expect("pack text")).expect("pack hex");
    let anchor = anchor_of(&server, Suite::Sm2).await;
    let outcome = verify_pack(&bytes, Some(&anchor), pack_now(&doc), DEFAULT_MAX_AGE_SECS);
    assert_eq!(outcome.grade.token(), "pass");
    assert_eq!(outcome.trust_marker.map(|t| t.as_str()), Some("attested"));
    server.stop().await;
}

#[tokio::test]
async fn co_signature_pack_carries_both_suites_on_one_body() {
    let (server, id) = spawn("ecdsa-p256,sm2").await;
    let resp = mint(&server, &id, json!({})).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&resp);
    let signatures = doc["signatures"].as_array().expect("signature list");
    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0]["suite"], "ecdsa-p256");
    assert_eq!(signatures[1]["suite"], "sm2");
    assert_eq!(doc["signature"]["suite"], "ecdsa-p256"); // default first

    let bytes = hex_decode(doc["pack"].as_str().expect("pack text")).expect("pack hex");
    let now = pack_now(&doc);
    // A verifier pinning both anchors: every slot verifies.
    let anchors = vec![
        anchor_of(&server, Suite::EcdsaP256).await,
        anchor_of(&server, Suite::Sm2).await,
    ];
    let outcome = verify_pack_with_anchors(&bytes, &anchors, now, DEFAULT_MAX_AGE_SECS);
    assert_eq!(outcome.grade.token(), "pass");
    // The cryptographic reading reports both slots verified.
    let crypto = outcome
        .readings
        .iter()
        .find(|r| r.name == "cryptographic")
        .expect("cryptographic reading");
    assert!(crypto.detail.contains("2/2"), "{crypto:?}");

    // A verifier pinning only the EU P-256 anchor: the SM2 slot
    // degrades per suite — the pack reads degraded, not failed.
    let eu_only = vec![anchors[0]];
    let outcome = verify_pack_with_anchors(&bytes, &eu_only, now, DEFAULT_MAX_AGE_SECS);
    assert_eq!(outcome.grade.token(), "degraded");
    let crypto = outcome
        .readings
        .iter()
        .find(|r| r.name == "cryptographic")
        .expect("cryptographic reading");
    assert!(crypto.detail.contains("1/2"), "{crypto:?}");
    server.stop().await;
}

#[tokio::test]
async fn per_request_suite_overrides_the_deployment_policy() {
    let (server, id) = spawn("ecdsa-p256").await;
    let resp = mint(&server, &id, json!({ "suite": "sm2" })).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["signature"]["suite"], "sm2");

    // A per-request co-signature list works too.
    let resp = mint(&server, &id, json!({ "suite": "ecdsa-p256,sm2" })).await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["signatures"].as_array().unwrap().len(), 2);

    // Refused loudly: unknown token, non-computed suite.
    let resp = mint(&server, &id, json!({ "suite": "wat" })).await;
    assert_eq!(resp.status, 400);
    let resp = mint(&server, &id, json!({ "suite": "ml-dsa-87" })).await;
    assert_eq!(resp.status, 400);
    server.stop().await;
}

#[tokio::test]
async fn verdict_reports_every_minted_suite() {
    let (server, id) = spawn("ecdsa-p256,sm2").await;
    let resp = get(&server.base_url, &format!("/passports/{id}/verdict")).await;
    assert_eq!(resp.status, 200, "{}", resp.body_string());
    let tier_a = &json_of(&resp)["tier_a"];
    let signatures = tier_a["signatures"].as_array().expect("signatures");
    assert_eq!(signatures.len(), 2);
    assert_eq!(tier_a["signature"]["suite"], "ecdsa-p256");
    server.stop().await;
}

#[tokio::test]
async fn discovery_declares_the_configured_suites() {
    let (server, _id) = spawn("ecdsa-p256,sm2").await;
    let doc = json_of(&get(&server.base_url, "/").await);
    let packs = doc["signatures"]["packs"].as_str().expect("packs text");
    assert!(packs.contains("ecdsa-p256 + sm2"), "{packs}");
    server.stop().await;
}
